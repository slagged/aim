"""Local builds must isolate inputs, retain failures, and avoid SSH entirely."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aimcmp.build import build, BuildError, effective_recipe, local_path


class LocalBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root/'sources').mkdir()
        (self.root/'sources/main.c').write_text('first source')
        (self.root/'sources/build.cmd').write_text('build fixture')
        self.target = {'name':'fixture', 'build':{'backend':'local', 'environment':'C:/native/env.cmd',
            'source_dir':'sources', 'files':['main.c', 'build.cmd'], 'script':'build.cmd',
            'artifacts':['builds/main.obj'], 'download_dir':'artifacts', 'flags':'/O1'}}

    def test_each_build_restages_and_copies_only_successful_artifacts(self):
        workdirs = []
        def compile(environment, script, timeout):
            workdirs.append(script.parent)
            self.assertEqual((script.parent/'main.c').read_text(), 'first source' if len(workdirs)==1 else 'second source')
            self.assertFalse((script.parent/'builds').exists())
            self.assertEqual((script.parent/'aimcmp-flags.txt').read_text().strip(), '/O1' if len(workdirs)==1 else '/O2')
            (script.parent/'builds').mkdir()
            (script.parent/'builds/main.obj').write_text('new artifact')
            return 'compiler output'
        with patch('aimcmp.build.local_run', side_effect=compile), patch('aimcmp.build.run') as ssh:
            result = build(self.root/'project.json', self.target)
            (self.root/'sources/main.c').write_text('second source')
            build(self.root/'project.json', self.target, flags='/O2', upload=False)
            ssh.assert_not_called()
        self.assertEqual(result['backend'], 'local')
        self.assertNotEqual(workdirs[0], workdirs[1])
        self.assertTrue(all(not path.exists() for path in workdirs))
        self.assertEqual((self.root/'artifacts/main.obj').read_text(), 'new artifact')

    def test_failed_build_retains_log_and_does_not_publish_stale_product(self):
        (self.root/'artifacts').mkdir()
        (self.root/'artifacts/main.obj').write_text('previous successful artifact')
        with patch('aimcmp.build.local_run', side_effect=RuntimeError('compiler error C2143')):
            with self.assertRaises(BuildError) as failure:
                build(self.root/'project.json', self.target)
        self.assertEqual(failure.exception.stage, 'build-local')
        self.assertIn('C2143', Path(failure.exception.log_path).read_text())
        self.assertEqual((self.root/'artifacts/main.obj').read_text(), 'previous successful artifact')

    def test_batch_paths_and_flags_reject_shell_expansion(self):
        for path in ('C:/native/%PATH%/env.cmd', 'C:/native/a&b.cmd'):
            with self.assertRaises(ValueError):
                local_path(path)
        with self.assertRaises(ValueError):
            build(self.root/'project.json', self.target, flags='/O1 & unexpected')

    def test_recipe_override_does_not_rewrite_public_profile(self):
        config = {'backend':'local', 'environment':'C:/native/env.cmd',
                  'recipe_data':{'toolchain':{'environment':'C:/VS2003/env.cmd'}}}
        recipe = effective_recipe(config)
        self.assertTrue(recipe['toolchain']['environment'].endswith('/native/env.cmd'))
        self.assertEqual(config['recipe_data']['toolchain']['environment'], 'C:/VS2003/env.cmd')
