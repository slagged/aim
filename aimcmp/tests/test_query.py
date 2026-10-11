"""Focused exports must not enumerate every function and must close owned views."""
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch
import tempfile
import unittest
from aimcmp.pe import Image
from aimcmp.query import query, bounded, resolve_address

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT/'../originals/AIM/idlemon.dll'


class QueryTests(unittest.TestCase):
    def setup_view(self):
        function = NS(name='IdleSetEvent',start=0x1c00101e,type='void()',
                      basic_blocks=[NS(start=0x1c00101e,end=0x1c001034)],
                      hlil=NS(root=NS(lines=['previous_input = last_input','last_input = GetTickCount()'])),
                      vars=[NS(name='eax',type='uint32_t')])
        caller = NS(name='IdleKeybdHook',start=0x1c001034)
        refs = [NS(address=0x1c001041,function=caller)]
        function.caller_sites=refs
        # No functions property: exporting an entire view would fail this fixture.
        bv = NS(file=NS(close=Mock()),get_function_at=lambda addr:function if addr==function.start else None,
                get_symbol_at=lambda addr:None,get_symbols_by_name=lambda name:[],
                get_code_refs=lambda addr:refs,get_data_refs=lambda addr:[],
                get_code_refs_from=lambda addr,func,length: [0x1c002000],
                get_data_refs_from=lambda addr,length=None:[],
                get_data_var_at=lambda addr:NS(type=NS(width=4,__str__=lambda self:'uint32_t')))
        bn = NS(core_version=lambda:'fixture',load=Mock(return_value=bv))
        conn = NS(root=NS(import_module=lambda name:bn),close=Mock())
        return bv,bn,conn

    def args(self,directory,**updates):
        values = dict(fields=None,kind='function',side='original',limit=3,cache=directory,
                      refresh=False,bn_host='localhost',bn_port=18812)
        values.update(updates)
        return NS(**values)

    def test_focused_fields_truncate_and_reuse_cache(self):
        bv,bn,conn = self.setup_view()
        with tempfile.TemporaryDirectory() as directory, patch('aimcmp.query.rpyc.connect',return_value=conn):
            args = self.args(directory)
            first = query(Image(ORIGINAL),'0x1c00101e',args)
            self.assertEqual(first['errors'],[])
            self.assertTrue(first['fields']['assembly']['truncated'])
            self.assertEqual(first['fields']['callers']['items'][0]['function_name'],'IdleKeybdHook')
            self.assertEqual(first['fields']['types']['signature'],'void()')
            cached = query(Image(ORIGINAL),'0x1c00101e',args)
            self.assertTrue(cached['cached'])
            self.assertEqual(bn.load.call_count,1)
            bv.file.close.assert_called_once()
            args.limit=4
            query(Image(ORIGINAL),'0x1c00101e',args)
            self.assertEqual(bn.load.call_count,2)

    def test_missing_function_closes_view_and_does_not_cache(self):
        bv,bn,conn = self.setup_view()
        with tempfile.TemporaryDirectory() as directory, patch('aimcmp.query.rpyc.connect',return_value=conn):
            with self.assertRaisesRegex(ValueError,'function start'):
                query(Image(ORIGINAL),'0x1c001020',self.args(directory))
            bv.file.close.assert_called_once()
            conn.close.assert_called_once()
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_data_default_fields_and_read_width(self):
        bv,bn,conn = self.setup_view()
        with tempfile.TemporaryDirectory() as directory, patch('aimcmp.query.rpyc.connect',return_value=conn):
            result = query(Image(ORIGINAL),'0x1c003014',self.args(directory,kind='data',limit=8))
            self.assertEqual(set(result['fields']),{'references','types'})
            self.assertEqual(len(result['fields']['types']['bytes']),8)
            self.assertFalse(result['fields']['types']['bytes_truncated'])

    def test_ambiguous_name_fails(self):
        bv,bn,conn = self.setup_view()
        bv.get_symbols_by_name=lambda name:[NS(address=0x1c001000),NS(address=0x1c00100f)]
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            resolve_address(bv,Image(ORIGINAL),'same-name',None,'function')

    def test_mapping_id_resolves_without_function_enumeration(self):
        bv,bn,conn = self.setup_view()
        data = {'records':[{'id':'stable-event','name':'Renamed','kind':'function','address':0x1c00101e}]}
        self.assertEqual(resolve_address(bv,Image(ORIGINAL),'stable-event',data,'function'),0x1c00101e)

    def test_invalid_fields_fail_before_connect(self):
        with patch('aimcmp.query.rpyc.connect') as connect:
            with self.assertRaisesRegex(ValueError,'subset'):
                query(Image(ORIGINAL),'entry',self.args('unused',fields='assembly,unknown'))
            connect.assert_not_called()

    def test_partial_analysis_error_is_visible_and_not_cached(self):
        bv,bn,conn = self.setup_view()
        function = bv.get_function_at(0x1c00101e)
        function.hlil = None
        with tempfile.TemporaryDirectory() as directory, patch('aimcmp.query.rpyc.connect',return_value=conn):
            result = query(Image(ORIGINAL),'0x1c00101e',self.args(directory,fields='assembly,hlil'))
            self.assertEqual(result['outcome'],'analysis-error')
            self.assertIn('assembly',result['fields'])
            self.assertTrue(result['errors'][0].startswith('hlil:'))
            self.assertEqual(list(Path(directory).iterdir()),[])
            bv.file.close.assert_called_once()

    def test_annotation_edit_selects_a_different_query_cache(self):
        bv,bn,conn = self.setup_view()
        from aimcmp.mappings import create
        ledger = create(ORIGINAL)
        ledger['records'] = [{'id':'event','kind':'function','original':'0x1c00101e','name':'Event',
            'type':'void Event(void)','confidence':'supported','evidence':['initial'],'rebuilt':None}]
        with tempfile.TemporaryDirectory() as directory, patch('aimcmp.query.rpyc.connect',return_value=conn), patch('aimcmp.query.apply'):
            args = self.args(directory,fields='types')
            query(Image(ORIGINAL),'event',args,ledger)
            cached = query(Image(ORIGINAL),'event',args,ledger)
            self.assertTrue(cached['cached'])
            ledger['records'][0]['evidence'].append('new evidence')
            result = query(Image(ORIGINAL),'event',args,ledger)
            self.assertFalse(result['cached'])
            self.assertEqual(bn.load.call_count,2)
