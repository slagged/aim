"""Variant generation, batch failure retention, and verified promotion."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import json
import shutil
import tempfile
import unittest
import zipfile
import test_checkpoints as fixture
from aimcmp.variants import expand, safe_extract, run_variants, promote
from aimcmp.binja import pe_snapshot
from aimcmp.cli import write_report
from aimcmp.pe import Image


class ExpansionTests(unittest.TestCase):
    def test_cartesian_fragments_and_flags(self):
        spec = {'schema':1,'axes':[{'name':'body','choices':[{'name':'a','text':'A'},{'name':'b','text':'B'}]},
            {'name':'flags','choices':[{'name':'O1','flags':'/O1'},{'name':'O2','flags':'/O2'}]}]}
        rows = expand(spec,{'source.c':'start {{body}} end'})
        self.assertEqual(len(rows),4)
        self.assertEqual(rows[0]['sources']['source.c'],'start A end')
        self.assertEqual(rows[3]['flags'],'/O2')
        self.assertEqual(rows[3]['id'],'v0003')

    def test_unresolved_markers_and_limits_fail(self):
        spec = {'schema':1,'max_variants':1,'axes':[{'name':'x','choices':[{'name':'a','text':'A'},{'name':'b','text':'B'}]}]}
        with self.assertRaisesRegex(ValueError,'max_variants'):
            expand(spec,{'source.c':'{{x}}'})
        spec['max_variants']=2
        with self.assertRaisesRegex(ValueError,'unresolved'):
            expand(spec,{'source.c':'{{x}} {{missing}}'})

    def test_archive_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            with zipfile.ZipFile(folder/'bad.zip','w') as zipped:
                zipped.writestr('../outside','bad')
            with self.assertRaisesRegex(ValueError,'Unsafe'):
                safe_extract(folder/'bad.zip',folder/'returned')

    def test_unsafe_flags_rejected(self):
        spec = {'schema':1,'flags':'/O2 & unexpected',
                'axes':[{'name':'x','choices':[{'name':'a','text':'A'}]}]}
        with self.assertRaisesRegex(ValueError,'unsupported'):
            expand(spec,{'source.c':'{{x}}'})


class VariantWorkflowTests(unittest.TestCase):
    def setUp(self):
        fixture.CheckpointTests.setUp(self)
        project = json.loads(self.project.read_text())
        project['batch_archive_tool']='C:/7z.exe'
        self.project.write_text(json.dumps(project))
        (self.root/'spec').mkdir()
        (self.root/'spec/template.c').write_text('source {{body}}')
        self.spec = self.root/'spec/spec.json'
        self.spec.write_text(json.dumps({'schema':1,'templates':{'candidate.c':'template.c'},
            'axes':[{'name':'body','choices':[{'name':'good','text':'good'},{'name':'bad','text':'bad'}]}]}))
        self.args = SimpleNamespace()

    def fake_batch(self,host,remote,tool,folder):
        self.assertIn('/variants/',remote)
        with zipfile.ZipFile(folder/'artifacts.zip','w') as zipped:
            for index in range(2):
                name = f'v{index:04d}'
                zipped.writestr(name+'/exit-code.txt','0' if index==0 else '1')
                zipped.writestr(name+'/build.log','compiled' if index==0 else 'compiler error C2143')
                if index==0:
                    for file in ('candidate.dll','candidate.map'):
                        zipped.write(self.root/'artifacts'/file,name+'/builds/'+file)

    def run_matrix(self):
        with patch('aimcmp.variants.remote_batch',side_effect=self.fake_batch), patch('aimcmp.variants.print'):
            return run_variants(self.project,self.target,self.spec,'experiment',self.args,
                                lambda image,args:pe_snapshot(image),write_report)

    def test_failed_compile_is_retained_and_other_variant_ranks(self):
        manifest,status = self.run_matrix()
        self.assertEqual(status,1)
        self.assertEqual(manifest['records'][0]['variant'],'v0000')
        self.assertTrue(manifest['records'][0]['summary']['code_sections_exact'])
        self.assertEqual(manifest['records'][1]['status'],'failed')
        self.assertIn('C2143',(self.root/'checkpoints/fixture/experiment-v0001/build.log').read_text())
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'frozen source\n')
        source = self.root/'checkpoints/fixture/experiment-v0000/sources/candidate.c'
        self.assertEqual(source.read_text(),'source good')

    def test_local_batch_keeps_failed_variant_without_ssh_or_archiver(self):
        self.target['build'].update(backend='local', environment='C:/native/env.cmd')
        self.target['build'].pop('remote_dir')
        self.target['build'].pop('ssh')
        project = json.loads(self.project.read_text())
        project['targets'][0] = self.target
        project.pop('batch_archive_tool')
        self.project.write_text(json.dumps(project))
        def compile(environment, script, timeout):
            directory = script.parent
            if (directory/'candidate.c').read_text() == 'source bad':
                raise RuntimeError('compiler error C2143')
            (directory/'builds').mkdir()
            for file in ('candidate.dll', 'candidate.map'):
                shutil.copyfile(self.root/'artifacts'/file, directory/'builds'/file)
            return 'compiled locally'
        with patch('aimcmp.variants.local_run', side_effect=compile), patch('aimcmp.variants.remote_batch') as remote, patch('aimcmp.variants.print'):
            manifest, status = run_variants(self.project, self.target, self.spec, 'local-experiment',
                self.args, lambda image,args:pe_snapshot(image), write_report)
            remote.assert_not_called()
        self.assertEqual(status, 1)
        self.assertEqual(manifest['backend'], 'local')
        self.assertTrue(manifest['records'][0]['summary']['code_sections_exact'])
        self.assertEqual(manifest['records'][1]['status'], 'failed')
        self.assertFalse((self.root/'experiments/runs/fixture/local-experiment/artifacts.zip').exists())

    def test_promotion_is_explicit_verifies_bytes_and_preserves_edits(self):
        self.run_matrix()
        (self.root/'sources/candidate.c').write_text('later edit')
        result = promote(self.project,self.target,'experiment','v0000',True)
        self.assertTrue(result['raw_code_verified'])
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'source good')
        self.assertTrue(Path(result['backup_path']).is_dir())

    def test_failed_variant_cannot_promote(self):
        self.run_matrix()
        with self.assertRaisesRegex(ValueError,'missing or failed'):
            promote(self.project,self.target,'experiment','v0001')

    def test_require_exact_rejects_mismatch_before_promotion(self):
        path = self.root/'artifacts/candidate.dll'
        image = Image(path)
        data = bytearray(path.read_bytes())
        offset = image.pe.get_offset_from_rva(0x1002)
        data[offset:offset+4]=(image.base+0x2004).to_bytes(4,'little')
        path.write_bytes(data)
        self.run_matrix()
        with self.assertRaisesRegex(ValueError,'does not match raw'):
            promote(self.project,self.target,'experiment','v0000',True)
        self.assertEqual((self.root/'sources/candidate.c').read_text(),'frozen source\n')

    def test_modified_run_cannot_promote(self):
        self.run_matrix()
        path = self.root/'experiments/runs/fixture/experiment/run.json'
        path.write_text(path.read_text()+' ')
        with self.assertRaisesRegex(ValueError,'integrity'):
            promote(self.project,self.target,'experiment','v0000')
