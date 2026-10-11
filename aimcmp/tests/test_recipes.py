"""Recipes must preserve ABI/link order and freeze their reproducible inputs."""
from pathlib import Path
import copy
import json
import unittest
from aimcmp.recipes import load_recipe, render_recipe
from aimcmp.config import load_project, portable_target


REPO = Path(__file__).resolve().parents[2]


class RecipeTests(unittest.TestCase):
    def recipe(self, name):
        return load_recipe(REPO/'targets', '../build/recipes/'+name+'.json')[0]

    def test_idlemon_preserves_shared_section_resource_and_entry_point(self):
        script = render_recipe(self.recipe('idlemon'))
        self.assertIn('/entry:DllMain@12', script)
        self.assertIn('/section:.aimshar,RWS', script)
        self.assertIn('rc /fobuilds\\idlemon.res idlemon.rc', script)
        self.assertIn('builds\\idlemon.obj builds\\idlemon.res kernel32.lib user32.lib', script)

    def test_shared_launcher_recipe_preserves_define_escaping_and_library_order(self):
        script = render_recipe(self.recipe('launchers'))
        self.assertIn('/DAIM_ACTION=\\"ShareFile\\"', script)
        self.assertEqual(script.count('kernel32.lib user32.lib advapi32.lib'), 2)
        self.assertIn('/entry:WinMain@16', script)
        self.assertIn('/stack:0x1000', script)
        self.assertIn('set /p AIMCMP_CFLAGS=<aimcmp-flags.txt', script)

    def test_command_injection_and_path_escape_are_rejected(self):
        recipe = self.recipe('launchers')
        for bad in ('/O2 & exit', '/O2\nexit'):
            with self.subTest(flags=bad):
                value = copy.deepcopy(recipe)
                value['flags'] = bad
                with self.assertRaisesRegex(ValueError, 'options'):
                    render_recipe(value)
        recipe['products'][0]['source'] = '../outside.cpp'
        with self.assertRaisesRegex(ValueError, 'relative paths'):
            render_recipe(recipe)

    def test_manifest_derives_products_files_and_flags_without_writeback(self):
        path = REPO/'targets/project.json'
        public = json.loads(path.read_text())
        project = load_project(path)
        for base, target in zip(public['targets'], project['targets']):
            config = target['build']
            self.assertEqual(config['script'], 'aimcmp-build.cmd')
            self.assertNotIn('build.cmd', config['files'])
            self.assertEqual(Path(config['artifacts'][0]).stem, target['name'])
            self.assertEqual(config['flags'], config['recipe_data']['flags'])
            self.assertEqual(len(config['_recipe_inputs']), 2)
            self.assertEqual(portable_target(public, target), base)
