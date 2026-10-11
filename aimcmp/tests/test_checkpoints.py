"""Checkpoints must bind frozen inputs to evidence and preserve later edits."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy
import json
import shutil
import tempfile
import unittest
from aimcmp.checkpoints import save_checkpoint, compare_checkpoints, restore_checkpoint, verify, location
from aimcmp.binja import pe_snapshot
from aimcmp.cli import write_report
from aimcmp.build import BuildError
from aimcmp.pe import sha256, Image

ROOT = Path(__file__).resolve().parents[1]


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original = self.root/'original.dll'
        self.original.write_bytes((ROOT/'../originals/AIM/idlemon.dll').read_bytes())
        (self.root/'sources').mkdir()
        (self.root/'sources/candidate.c').write_text('frozen source\n')
        (self.root/'sources/build.cmd').write_text('fixture build recipe\n')
        (self.root/'artifacts').mkdir()
        (self.root/'artifacts/candidate.dll').write_bytes((ROOT/'../targets/builds/idlemon/idlemon.dll').read_bytes())
        (self.root/'artifacts/candidate.map').write_bytes((ROOT/'../targets/builds/idlemon/idlemon.map').read_bytes())
        self.target = {'name':'fixture', 'original':'original.dll', 'rebuilt':'artifacts/candidate.dll',
            'map':'artifacts/candidate.map', 'build':{'ssh':'win7', 'remote_dir':'C:/fixture',
            'source_dir':'sources', 'files':['candidate.c','build.cmd'], 'script':'build.cmd',
            'artifacts':['builds/candidate.dll','builds/candidate.map'], 'download_dir':'artifacts', 'flags':'/O2'}}
        self.project = self.root/'project.json'
        self.other = {'name':'untouched', 'original':'original.dll', 'note':'keep this target'}
        self.project.write_text(json.dumps({'targets':[self.target,self.other]}))
        self.args = SimpleNamespace(flags=None, require_exact=True)

    def fake_build(self, project_path, target):
        directory = self.root/target['build']['download_dir']
        directory.mkdir(parents=True, exist_ok=True)
        for name in ('candidate.dll','candidate.map'):
            (directory/name).write_bytes((self.root/'artifacts'/name).read_bytes())
        (directory/'build.log').write_text('fixture build completed')
        (directory/'aimcmp-flags.txt').write_text(target['build']['flags'])
        return {'elapsed_seconds':0, 'artifacts_dir':str(directory), 'log_path':str(directory/'build.log')}

    def save(self, name='first'):
        with patch('aimcmp.workflow.build', side_effect=self.fake_build):
            result, status = save_checkpoint(self.project, self.target, name, self.args,
                                             lambda image,args:pe_snapshot(image), write_report)
        self.assertEqual(status, 0)
        return location(self.project,self.target,name), result

    def test_build_uses_frozen_sources_and_isolated_remote_directory(self):
        def build(project, target):
            self.assertEqual((self.root/target['build']['source_dir']/'candidate.c').read_text(), 'frozen source\n')
            self.assertIn('/checkpoints/first-', target['build']['remote_dir'])
            (self.root/'sources/candidate.c').write_text('edit made during build')
            return self.fake_build(project,target)
        with patch('aimcmp.workflow.build', side_effect=build):
            result, status = save_checkpoint(self.project,self.target,'first',self.args,
                                             lambda image,args:pe_snapshot(image),write_report)
        folder = Path(result['path'])
        self.assertEqual((folder/'sources/candidate.c').read_text(),'frozen source\n')
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'edit made during build')
        self.assertEqual(verify(folder)['status'],'complete')

    def test_existing_checkpoint_cannot_be_overwritten(self):
        folder, result = self.save()
        old = (folder/'checkpoint.json').read_bytes()
        with self.assertRaises(FileExistsError):
            self.save()
        self.assertEqual((folder/'checkpoint.json').read_bytes(),old)

    def test_compare_is_offline_and_detects_source_flags_changes(self):
        first,_ = self.save('first')
        (self.root/'sources/candidate.c').write_text('different source')
        self.args.flags = '/O1'
        second,_ = self.save('second')
        with patch('aimcmp.workflow.build') as remote:
            result = compare_checkpoints(first,second)
            remote.assert_not_called()
        self.assertEqual(result['delta']['changed_functions'],[])
        self.assertEqual(result['checkpoint_delta']['changed_source_or_mapping_paths'],['sources/candidate.c'])
        self.assertEqual(result['checkpoint_delta']['configured_flags'],{'before':'/O2','after':'/O1'})

    def test_restore_and_backup_restore_preserve_later_edits_and_other_target(self):
        folder,_ = self.save()
        (self.root/'sources/candidate.c').write_text('later source edits')
        project = json.loads(self.project.read_text())
        project['targets'][0]['build']['flags'] = '/Ox'
        self.project.write_text(json.dumps(project))
        current = project['targets'][0]
        restored = restore_checkpoint(self.project,current,'first')
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'frozen source\n')
        updated = json.loads(self.project.read_text())
        self.assertEqual(updated['targets'][0]['build']['flags'],'/O2')
        self.assertEqual(updated['targets'][1],self.other)
        backup = verify(Path(restored['backup_path']))
        self.assertEqual(backup['checkpoint_kind'],'working-state')
        restore_checkpoint(self.project,updated['targets'][0],restored['backup'])
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'later source edits')
        self.assertEqual(json.loads(self.project.read_text())['targets'][0]['build']['flags'],'/Ox')
        self.assertFalse((self.root/'artifacts/build.log').exists())
        self.assertTrue((folder/'checkpoint.json').is_file())

    def test_corruption_rejected_before_working_files_change(self):
        folder,_ = self.save()
        (folder/'sources/candidate.c').write_text('damaged checkpoint')
        (self.root/'sources/candidate.c').write_text('keep current')
        before = list(folder.parent.iterdir())
        with self.assertRaisesRegex(ValueError,'integrity'):
            restore_checkpoint(self.project,self.target,'first')
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'keep current')
        self.assertEqual(list(folder.parent.iterdir()),before)

    def test_escape_restore_path_is_rejected_before_backup(self):
        folder,_ = self.save()
        path = folder/'checkpoint.json'
        manifest = json.loads(path.read_text())
        manifest['restore_files'][0]['path'] = '../outside.c'
        path.write_text(json.dumps(manifest))
        (folder/'checkpoint.sha256').write_text(sha256(path))
        with self.assertRaisesRegex(ValueError,'inside'):
            restore_checkpoint(self.project,self.target,'first')
        self.assertEqual(len(list(folder.parent.iterdir())),1)

    def test_failed_build_remains_failed_and_cannot_restore(self):
        with patch('aimcmp.workflow.build', side_effect=BuildError('build','syntax error',self.root/'build.log')):
            with self.assertRaisesRegex(RuntimeError,'evidence retained'):
                save_checkpoint(self.project,self.target,'failed',self.args,lambda image,args:pe_snapshot(image),write_report)
        folder = location(self.project,self.target,'failed')
        self.assertEqual(json.loads((folder/'checkpoint.json').read_text())['status'],'failed')
        with self.assertRaisesRegex(ValueError,'incomplete or failed'):
            restore_checkpoint(self.project,self.target,'failed')

    def test_invalid_name_cannot_escape_checkpoint_root(self):
        with self.assertRaisesRegex(ValueError,'simple names'):
            self.save('../escape')

    def test_restore_failure_rolls_back_from_backup(self):
        folder,_ = self.save()
        (self.root/'sources/candidate.c').write_text('preserve this edit')
        from aimcmp.checkpoints import copy_file
        failures = []
        def faulty(source,destination):
            if str(source).startswith(str(folder)) and Path(source).name=='build.cmd' and not failures:
                failures.append(True)
                raise OSError('simulated write failure')
            copy_file(source,destination)
        with patch('aimcmp.checkpoints.copy_file', side_effect=faulty):
            with self.assertRaisesRegex(RuntimeError,'rolled back'):
                restore_checkpoint(self.project,self.target,'first')
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'preserve this edit')

    def test_original_cannot_be_a_restore_destination(self):
        folder,_ = self.save()
        path = folder/'checkpoint.json'
        manifest = json.loads(path.read_text())
        manifest['restore_files'][0]['path']='original.dll'
        path.write_text(json.dumps(manifest))
        (folder/'checkpoint.sha256').write_text(sha256(path))
        with self.assertRaisesRegex(ValueError,'original'):
            restore_checkpoint(self.project,self.target,'first')

    def test_manifest_edit_invalidates_checkpoint(self):
        folder,_ = self.save()
        path = folder/'checkpoint.json'
        manifest = json.loads(path.read_text())
        manifest['restore_target']['build']['flags'] = '/different'
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError,'manifest integrity'):
            restore_checkpoint(self.project,self.target,'first')
        self.assertEqual(len(list(folder.parent.iterdir())),1)

    def test_restore_retains_relocated_original_path(self):
        self.save()
        (self.root/'inputs').mkdir()
        (self.root/'inputs/original.dll').write_bytes(self.original.read_bytes())
        project = json.loads(self.project.read_text())
        project['targets'][0]['original']='inputs/original.dll'
        self.project.write_text(json.dumps(project))
        restore_checkpoint(self.project,project['targets'][0],'first')
        self.assertEqual(json.loads(self.project.read_text())['targets'][0]['original'],'inputs/original.dll')

    def test_sibling_sources_save_restore_and_old_checkpoint_rebase(self):
        # Model aimcmp/ and src/ inside one explicit repository boundary.
        previous = self.root
        workbench = previous/'workbench'
        workbench.mkdir()
        for path in list(previous.iterdir()):
            if path != workbench:
                shutil.move(str(path), str(workbench/path.name))
        self.root = workbench
        self.project = workbench/'project.json'
        self.original = workbench/'original.dll'
        folder, _ = self.save('before-move')
        sealed = (folder/'checkpoint.json').read_bytes()
        source = previous/'src'
        shutil.move(str(workbench/'sources'), str(source))
        project = json.loads(self.project.read_text())
        project['workspace_root'] = '..'
        project['targets'][0]['build']['source_dir'] = '../src'
        self.project.write_text(json.dumps(project))
        self.target = project['targets'][0]
        (source/'candidate.c').write_text('edited after move')
        restored = restore_checkpoint(self.project, self.target, 'before-move')
        self.assertEqual((source/'candidate.c').read_text(), 'frozen source\n')
        self.assertFalse((workbench/'sources').exists())
        self.assertEqual(json.loads(self.project.read_text())['targets'][0]['build']['source_dir'], '../src')
        self.assertEqual((folder/'checkpoint.json').read_bytes(), sealed)
        restore_checkpoint(self.project, self.target, restored['backup'])
        self.assertEqual((source/'candidate.c').read_text(), 'edited after move')
        self.save('after-move')

    def test_workspace_boundary_still_rejects_escape(self):
        from aimcmp.checkpoints import validate_destination
        project = json.loads(self.project.read_text())
        project['workspace_root'] = '..'
        self.project.write_text(json.dumps(project))
        with self.assertRaisesRegex(ValueError, 'inside'):
            validate_destination(self.root, '../../outside.txt', self.project, self.original)

    def test_restore_keeps_machine_overrides_private_and_ledger_path_portable(self):
        from aimcmp.cli import load_target
        from aimcmp.mappings import create
        ledger_path = self.root/'mapping.json'
        ledger_path.write_text(json.dumps(create(self.original)))
        project = json.loads(self.project.read_text())
        project['local_config'] = 'machine.json'
        project['targets'][0]['mapping'] = 'mapping.json'
        project['targets'][0]['build']['ssh'] = 'public-vm'
        project['targets'][0]['build']['remote_dir'] = 'C:/public/build'
        self.project.write_text(json.dumps(project))
        (self.root/'machine.json').write_text(json.dumps({'schema':1,
            'targets':{'fixture':{'ssh':'private-vm', 'remote_dir':'C:/private/build'}}}))
        _, self.target = load_target(self.project, 'fixture')
        folder, _ = self.save()
        sealed = (folder/'checkpoint.json').read_bytes()
        restore_checkpoint(self.project, self.target, 'first')
        restored = json.loads(self.project.read_text())['targets'][0]
        self.assertEqual(restored['build']['ssh'], 'public-vm')
        self.assertEqual(restored['build']['remote_dir'], 'C:/public/build')
        self.assertEqual(load_target(self.project, 'fixture')[1]['build']['ssh'], 'private-vm')
        self.assertEqual(json.loads(ledger_path.read_text())['original']['path'], 'original.dll')
        self.assertEqual((folder/'checkpoint.json').read_bytes(), sealed)

    def test_checkpoint_freezes_and_restores_recipe_inputs(self):
        recipe_path = self.root/'recipe.json'
        recipe_path.write_text('original recipe bytes')
        self.target['build']['_recipe_inputs'] = [str(recipe_path)]
        project = json.loads(self.project.read_text())
        project['targets'][0] = self.target
        self.project.write_text(json.dumps(project))
        def build(path, target):
            recipe_path.write_text('edit made during build')
            return self.fake_build(path, target)
        with patch('aimcmp.workflow.build', side_effect=build):
            result, status = save_checkpoint(self.project,self.target,'recipe',self.args,
                lambda image,args:pe_snapshot(image),write_report)
        folder = Path(result['path'])
        manifest = verify(folder)
        self.assertEqual(status,0)
        self.assertEqual((folder/'recipe/0/recipe.json').read_text(),'original recipe bytes')
        self.assertTrue(any(file['role']=='recipe' for file in manifest['restore_files']))
        restore_checkpoint(self.project,self.target,'recipe')
        self.assertEqual(recipe_path.read_text(),'original recipe bytes')

    def test_mismatch_is_saved_and_require_exact_returns_two(self):
        path = self.root/'artifacts/candidate.dll'
        image = Image(path)
        data = bytearray(path.read_bytes())
        offset = image.pe.get_offset_from_rva(0x1002)
        data[offset:offset+4] = (image.base+0x2004).to_bytes(4,'little')
        path.write_bytes(data)
        with patch('aimcmp.workflow.build', side_effect=self.fake_build):
            result, status = save_checkpoint(self.project,self.target,'mismatch',self.args,
                                             lambda image,args:pe_snapshot(image),write_report)
        self.assertEqual(status,2)
        self.assertEqual(result['status'],'complete')
        self.assertFalse(verify(Path(result['path']))['summary']['code_sections_exact'])
