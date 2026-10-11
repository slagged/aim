"""Exercise iteration evidence and stage failures without remote side effects."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy
import json
import tempfile
import unittest
from aimcmp.pe import Image
from aimcmp.binja import pe_snapshot
from aimcmp.compare import compare
from aimcmp.cli import write_report
from aimcmp.iteration import compact_report, render_text
from aimcmp.workflow import iterate
from aimcmp.build import build, BuildError

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / '../originals/AIM/idlemon.dll'
REBUILT = ROOT / '../targets/builds/idlemon/idlemon.dll'


def comparison(a=ORIGINAL, b=REBUILT):
    left, right = Image(a), Image(b)
    return compare(left, right, pe_snapshot(left), pe_snapshot(right))


def arguments(directory, **changes):
    values = dict(output_dir=str(directory), baseline=None, no_build=True,
                  require_exact=True, diff_limit=3, function_limit=20)
    values.update(changes)
    return SimpleNamespace(**values)


TARGET = {'name': 'fixture', 'original': str(ORIGINAL), 'rebuilt': str(REBUILT)}


class IterationTests(unittest.TestCase):
    def test_timestamp_only_rebuild_is_not_a_changed_function(self):
        baseline = comparison()
        current = copy.deepcopy(baseline)
        current['rebuilt']['timestamp'] += 5
        current['rebuilt']['sha256'] = 'different-whole-file-hash'
        current['metadata_diff']['timestamp']['rebuilt'] += 5
        brief = compact_report(current, baseline)
        self.assertEqual(brief['functions'], [])
        self.assertEqual(brief['delta']['changed_functions'], [])
        self.assertFalse(brief['delta']['code_sections_changed'])
        self.assertTrue(brief['delta']['whole_file_changed'])
        self.assertIn('timestamp', brief['delta']['metadata_changes'])
        self.assertEqual(brief['whole_file_status'], 'timestamps-only')

    def test_wrong_import_is_visible_with_both_identities_and_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory)/'wrong-import.dll'
            image = Image(REBUILT)
            source = bytearray(REBUILT.read_bytes())
            offset = image.pe.get_offset_from_rva(0x1002)
            source[offset:offset+4] = (image.base+0x2004).to_bytes(4,'little')
            changed.write_bytes(source)
            brief = compact_report(comparison(ORIGINAL, changed), comparison())
            function = brief['functions'][0]
            self.assertEqual(function['status'], 'different')
            row = function['first_differences'][0]
            self.assertEqual(row['original']['references'][0]['identity'], 'import:KERNEL32.DLL!GetTickCount')
            self.assertEqual(row['rebuilt']['references'][0]['identity'], 'import:KERNEL32.DLL!GetProcAddress')
            self.assertEqual(brief['delta']['summary_delta']['exact_functions'], -1)
            self.assertLess(brief['delta']['summary_delta']['normalized_coverage_percent'], 0)
            self.assertIn('GetProcAddress', render_text(brief))

    def test_incompatible_original_baseline_is_rejected(self):
        current = comparison()
        baseline = copy.deepcopy(current)
        baseline['original']['sha256'] = 'other-binary'
        with self.assertRaisesRegex(ValueError, 'different original'):
            compact_report(current, baseline)

    def test_compact_baseline_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'full aimcmp'):
            compact_report(comparison(), compact_report(comparison()))

    def test_empty_baseline_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'full aimcmp'):
            compact_report(comparison(), {})

    def test_require_exact_returns_two_for_changed_code(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            changed = folder/'wrong-import.dll'
            image = Image(REBUILT)
            source = bytearray(REBUILT.read_bytes())
            offset = image.pe.get_offset_from_rva(0x1002)
            source[offset:offset+4] = (image.base+0x2004).to_bytes(4, 'little')
            changed.write_bytes(source)
            target = dict(TARGET, rebuilt=str(changed))
            result, status = iterate(folder/'project.json', target, arguments(folder/'reports'),
                                     lambda image,args: pe_snapshot(image), write_report)
            self.assertEqual(status, 2)
            self.assertEqual(result['outcome'], 'incomplete')
            self.assertTrue((folder/'reports/latest.json').is_file())

    def test_truncation_is_explicit_for_large_pending_lists(self):
        report = comparison()
        for function in report['functions']:
            function['status'] = 'missing'
        brief = compact_report(report, function_limit=2)
        self.assertEqual(len(brief['functions']), 2)
        self.assertEqual(brief['pending_function_count'], 8)
        self.assertTrue(brief['functions_truncated'])

    def test_two_iterations_reuse_previous_report_and_keep_full_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            args = arguments(folder/'reports')
            analyze = lambda image, args: pe_snapshot(image)
            first, status = iterate(folder/'project.json', TARGET, args, analyze, write_report)
            self.assertEqual(status, 0)
            self.assertIsNone(first['delta'])
            second, status = iterate(folder/'project.json', TARGET, args, analyze, write_report)
            self.assertEqual(status, 0)
            self.assertEqual(second['delta']['changed_functions'], [])
            self.assertTrue((folder/'reports/previous.json').is_file())
            full = json.loads((folder/'reports/latest.json').read_text())
            self.assertIn('original_hlil', full['functions'][0])
            self.assertTrue((folder/'reports/latest.html').is_file())

    def test_build_failure_preserves_baseline_and_identifies_upload_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            args = arguments(folder/'reports')
            analyze = lambda image, args: pe_snapshot(image)
            iterate(folder/'project.json', TARGET, args, analyze, write_report)
            latest = folder/'reports/latest.json'
            old = latest.read_bytes()
            args.no_build = False
            with patch('aimcmp.workflow.build', side_effect=BuildError('upload', 'connection lost', folder/'build.log')):
                result, status = iterate(folder/'project.json', TARGET, args, analyze, write_report)
            self.assertEqual(status, 1)
            self.assertEqual(result['error']['stage'], 'upload')
            self.assertEqual(latest.read_bytes(), old)
            self.assertTrue((folder/'reports/failure.json').is_file())

    def test_analysis_connection_failure_preserves_baseline_and_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            args = arguments(folder/'reports')
            iterate(folder/'project.json', TARGET, args, lambda image,args: pe_snapshot(image), write_report)
            old = (folder/'reports/latest.json').read_bytes()
            def analyze(image, args):
                if image.path == REBUILT.resolve():
                    raise ConnectionError('Binary Ninja disconnected')
                return pe_snapshot(image)
            result, status = iterate(folder/'project.json', TARGET, args, analyze, write_report)
            self.assertEqual(status, 1)
            self.assertEqual(result['error']['stage'], 'analyze-rebuilt')
            self.assertEqual((folder/'reports/latest.json').read_bytes(), old)

    def test_compile_failure_retains_remote_diagnostics_in_build_log(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder/'build.cmd').write_text('test fixture')
            target = {'name':'fixture','build':{'ssh':'win7','remote_dir':'C:/fixture',
                      'source_dir':'.','files':['build.cmd'],'script':'build.cmd',
                      'artifacts':[],'download_dir':'artifacts'}}
            def remote(args, timeout=300):
                if args[0] == 'ssh' and 'build.cmd' in args[-1]:
                    raise RuntimeError('compiler error C2143: missing semicolon')
                return 'completed stage'
            with patch('aimcmp.build.run', side_effect=remote):
                with self.assertRaises(BuildError) as caught:
                    build(folder/'project.json', target)
            self.assertEqual(caught.exception.stage, 'build')
            log = (folder/'artifacts/build.log').read_text()
            self.assertIn('C2143', log)
            self.assertIn('[upload]', log)

    def test_explicit_unknown_baseline_fails_before_remote_build(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            args = arguments(folder/'reports', baseline=str(folder/'missing.json'), no_build=False)
            with patch('aimcmp.workflow.build') as remote:
                result, status = iterate(folder/'project.json', TARGET, args, lambda image,args: pe_snapshot(image), write_report)
                remote.assert_not_called()
            self.assertEqual(status, 1)
            self.assertEqual(result['error']['stage'], 'baseline')


if __name__ == '__main__':
    unittest.main()
