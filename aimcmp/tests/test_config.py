"""Local machine settings must never become public reconstruction recipes."""
from pathlib import Path
import json
import tempfile
import unittest
from aimcmp.config import load_project, portable_target


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root/'project.json'
        self.base = {'local_config':'machine.json', 'targets':[{'name':'fixture',
            'build':{'ssh':'build-vm', 'remote_dir':'C:/build/fixture', 'source_dir':'src', 'flags':'/O2'}}],
            'toolchain':{'ssh':'build-vm', 'files':{'cl.exe':'C:/VS2003/cl.exe'}}}
        self.path.write_text(json.dumps(self.base))

    def local(self, value):
        (self.root/'machine.json').write_text(json.dumps(value))

    def test_missing_optional_local_config_uses_public_defaults(self):
        self.assertEqual(load_project(self.path), self.base)

    def test_machine_overrides_do_not_modify_public_file(self):
        before = self.path.read_bytes()
        self.local({'schema':1, 'targets':{'fixture':{'ssh':'local-vm', 'remote_dir':'D:/local/build'}},
                    'toolchain':{'ssh':'local-vm', 'files':{'link.exe':'D:/tools/link.exe'}},
                    'batch_archive_tool':'D:/tools/7z.exe'})
        effective = load_project(self.path)
        self.assertEqual(effective['targets'][0]['build']['ssh'], 'local-vm')
        self.assertEqual(effective['targets'][0]['build']['source_dir'], 'src')
        self.assertEqual(effective['toolchain']['files']['cl.exe'], 'C:/VS2003/cl.exe')
        self.assertEqual(effective['toolchain']['files']['link.exe'], 'D:/tools/link.exe')
        self.assertEqual(effective['batch_archive_tool'], 'D:/tools/7z.exe')
        self.assertEqual(self.path.read_bytes(), before)

    def test_local_recipe_or_unknown_target_overrides_are_rejected(self):
        for overrides in ({'fixture':{'flags':'/O1'}}, {'fixture':{'source_dir':'elsewhere'}}, {'missing':{'ssh':'vm'}}):
            with self.subTest(overrides=overrides):
                self.local({'schema':1, 'targets':overrides})
                with self.assertRaisesRegex(ValueError, 'known targets'):
                    load_project(self.path)

    def test_portable_writeback_preserves_flags_and_strips_machine_overrides(self):
        self.local({'schema':1, 'targets':{'fixture':{'ssh':'local-vm', 'timeout_seconds':999}}})
        target = load_project(self.path)['targets'][0]
        target['build']['flags'] = '/O1'
        portable = portable_target(self.base, target)
        self.assertEqual(portable['build']['ssh'], 'build-vm')
        self.assertNotIn('timeout_seconds', portable['build'])
        self.assertEqual(portable['build']['flags'], '/O1')
        self.assertEqual(target['build']['ssh'], 'local-vm')
