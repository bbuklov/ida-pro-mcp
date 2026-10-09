"""Full-output regressions against the actual fork source, without IDA.

Functions are loaded from this checkout via AST with decorators removed. Only
inert IDA adapters and database helper results are supplied; the output,
pagination, transport, and list behavior under test comes directly from source.
No database, sample, server, live capture, arbitrary script, or network
connection is opened by these tests. No runtime output adapter is installed.
"""
from __future__ import annotations

import ast
from collections import defaultdict, deque
import json
import os
from pathlib import Path
import sys
import types
import typing
import unittest
from unittest.mock import patch


def fork_source() -> Path:
    """Always execute the source in this checkout, rather than an installed package."""
    return Path(__file__).resolve().parents[1] / 'src' / 'ida_pro_mcp' / 'ida_mcp'


def load_functions(module: types.ModuleType, path: Path):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    module.__file__ = str(path)
    namespace = module.__dict__
    namespace.update({name: value for name, value in vars(typing).items()
                      if not name.startswith('__')})
    namespace.update(json=json, os=os, sys=sys, deque=deque, defaultdict=defaultdict)
    namespace.update(BasicBlock=dict, Argument=dict)
    # Constants relevant to pure helpers; non-literal expressions are not run.
    for node in tree.body:
        if isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    namespace[target.id] = value
    namespace.setdefault('_BORING_CONSTANTS', frozenset())
    tool_names = []
    functions = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(item, ast.Name) and item.id == 'tool'
                   for item in node.decorator_list):
                tool_names.append(node.name)
            node.decorator_list = []
            functions.append(node)
    executable = ast.Module(body=[ast.ImportFrom(module='__future__',
        names=[ast.alias(name='annotations')], level=0), *functions], type_ignores=[])
    ast.fix_missing_locations(executable)
    exec(compile(executable, str(path), 'exec'), namespace)
    return tool_names


class UnlimitedOutputTests(unittest.TestCase):
    def setUp(self):
        root = fork_source()
        upstream = types.ModuleType('ida_pro_mcp')
        upstream.__path__ = [str(root.parent)]
        package = types.ModuleType('ida_pro_mcp.ida_mcp')
        package.__path__ = [str(root)]
        self.server = types.SimpleNamespace(
            tools=types.SimpleNamespace(methods={}),
            registry=types.SimpleNamespace(methods={}))
        def register_tool(function):
            self.server.tools.methods[function.__name__] = function
            return function
        self.server.tool = register_tool
        package.MCP_SERVER = self.server
        self.modules = {}
        patched = {'ida_pro_mcp': upstream, 'ida_pro_mcp.ida_mcp': package}
        for name in ('rpc', 'utils', 'api_analysis', 'api_composite'):
            module = types.ModuleType('ida_pro_mcp.ida_mcp.' + name)
            module.__package__ = package.__name__
            module.MCP_SERVER = self.server
            names = load_functions(module, root / (name + '.py'))
            self.server.tools.methods.update({name: getattr(module, name) for name in names})
            self.modules[name] = module
            setattr(package, name, module)
            patched[module.__name__] = module
        self.count = 60000
        self.block_count = 8000
        self.code = '\n'.join(f'line_{i:05d} ' + 'x' * 110 for i in range(6500))
        self.func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1000 + 4 * self.count)
        idaapi = types.ModuleType('idaapi')
        idaapi.BADADDR = -1
        idaapi.get_func = lambda addr: self.func
        idaapi.getseg = lambda addr: types.SimpleNamespace(end_ea=self.func.end_ea)
        idaapi.get_segm_name = lambda seg: '.text'
        idaapi.get_func_name = lambda addr: 'inert_function'
        idaapi.insn_t = lambda: types.SimpleNamespace(itype=1)
        idaapi.decode_insn = lambda insn, addr: setattr(
            insn, 'itype', 2 if addr < 6000 else 1)
        idaapi.NN_call = idaapi.NN_callfi = idaapi.NN_callni = 1
        idaapi.FlowChart = lambda fn: (types.SimpleNamespace(
            start_ea=0x1000 + i * 4, end_ea=0x1004 + i * 4, type=0,
            succs=lambda: [], preds=lambda: []) for i in range(self.block_count))
        idautils = types.ModuleType('idautils')
        idautils.FuncItems = lambda addr: range(0x1000, 0x1000 + 4 * self.count, 4)
        idautils.CodeRefsTo = lambda addr, flags: range(6100)
        ida_lines = types.ModuleType('ida_lines')
        ida_lines.generate_disasm_line = lambda addr, flags: f'insn_{addr:x}'
        ida_lines.tag_remove = lambda value: value
        ida_funcs = types.ModuleType('ida_funcs')
        ida_funcs.get_func_name = lambda addr: 'inert_function'
        ida_name = types.ModuleType('ida_name')
        ida_name.get_ea_name = lambda addr: ''
        ida_typeinf = types.ModuleType('ida_typeinf')
        ida_typeinf.tinfo_t = lambda: object()
        ida_nalt = types.ModuleType('ida_nalt')
        ida_nalt.get_tinfo = lambda tif, addr: False
        ida_hexrays = types.ModuleType('ida_hexrays')
        ida_hexrays.init_hexrays_plugin = lambda: False
        for module in (idaapi, idautils, ida_lines, ida_funcs, ida_name,
                       ida_typeinf, ida_nalt, ida_hexrays):
            patched[module.__name__] = module
            for source_module in self.modules.values():
                setattr(source_module, module.__name__, module)
        for module in self.modules.values():
            module.parse_address = lambda addr: int(addr, 0)
            module.compact_whitespace = lambda value: value
        analysis = self.modules['api_analysis']
        analysis.decompile_function_safe = lambda *args, **kwargs: (self.code, None)
        analysis._collect_line_comments = lambda ea: []
        analysis._collect_line_refs = lambda ea: []
        analysis.get_stack_frame_variables_internal = lambda *args: []
        utils = self.modules['utils']
        utils.get_function = lambda addr, raise_error=False: {
            'addr': hex(addr), 'name': f'caller_{addr}'}
        for name in ('api_analysis', 'api_composite'):
            self.modules[name].get_callers = utils.get_callers
        self.modules['api_composite'].MCP_SERVER = self.server
        self.enterContext(patch.dict(sys.modules, patched))

    def test_transport_preserves_large_nested_result(self):
        payload = {'functions': [{'addr': hex(i), 'code': self.code,
                                  'lines': list(range(40))} for i in range(19)]}
        reply = {'structuredContent': payload,
                 'content': [{'type': 'text', 'text': json.dumps(payload)}],
                 'isError': False}
        returned = self.modules['rpc']._limit_output_response(reply)
        self.assertIs(returned, reply)
        self.assertNotIn('_meta', returned)
        self.assertEqual(len(returned['structuredContent']['functions']), 19)
        self.assertTrue(returned['structuredContent']['functions'][-1]['code'].endswith('x' * 110))

    def test_composite_keeps_body_and_all_compact_list_items(self):
        composite = self.modules['api_composite']
        self.assertEqual(composite._cap_decompile(self.code), (self.code, None))
        strings = [{'value': f'string_{i}'} for i in range(25)]
        self.assertEqual(composite._compact_strings(strings),
                         [item['value'] for item in strings])
        self.assertEqual(composite._compact_strings(strings, limit=5),
                         [item['value'] for item in strings[:5]])
        constants = [{'value': 0x10000 + i} for i in range(25)]
        self.assertEqual(len(composite._filter_constants(constants)), 25)
        self.assertEqual(len(composite._filter_constants(constants, limit=5)), 5)
        composite.decompile_function_safe = lambda *args, **kwargs: (self.code, None)
        composite.get_prototype = lambda func: 'void inert_function(void)'
        composite.extract_function_strings = lambda ea: strings
        composite.extract_function_constants = lambda ea: constants
        composite.get_callees = lambda addr: []
        composite.get_all_xrefs = lambda ea: {'to': [], 'from': []}
        composite.get_all_comments = lambda ea: []
        result = composite.analyze_function('0x1000')
        self.assertIsNone(result['error'])
        self.assertEqual(result['decompiled'], self.code)
        self.assertNotIn('decompile_truncated', result)
        self.assertEqual(result['strings'], [item['value'] for item in strings])
        self.assertEqual(len(result['constants']), 25)

    def test_line_page_preserves_requested_lines_without_character_budget(self):
        analysis = self.modules['api_analysis']
        page, line_count, total_lines, more = analysis._paginate_decompile_code(self.code, 0, 9000)
        self.assertEqual((page, line_count, total_lines, more), (self.code, 6500, 6500, False))
        long_lines = '\n'.join('L' * 70000 + str(i) for i in range(4))
        page, count, total, more = analysis._paginate_decompile_code(long_lines, 1, 2)
        self.assertEqual(page, '\n'.join(long_lines.split('\n')[1:3]))
        self.assertEqual((count, total, more), (2, 4, True))

    def test_refs_and_analysis_lists_have_no_hidden_budget(self):
        analysis = self.modules['api_analysis']
        refs = [{'addr': hex(i), 'name': 'R' * 500} for i in range(250)]
        result = {'addr': '0x1000', 'code': self.code}
        analysis._attach_decompile_refs(result, refs)
        self.assertEqual(result['refs'], refs)
        self.assertFalse(result.get('refs_truncated', False))
        items = list(range(5001))
        self.assertEqual(analysis._limit_items(items, 0), (items, False))
        self.assertEqual(analysis._limit_items(items, 200), (items[:200], True))

    def test_public_decompile_defaults_to_entire_body(self):
        decompile = self.server.tools.methods['decompile']
        result = decompile('0x1000')
        self.assertNotIn('error', result)
        self.assertEqual(result['code'], self.code)
        self.assertEqual(result['line_count'], 6500)
        self.assertEqual(result['cursor'], {'done': True})
        self.assertFalse(result.get('truncated', False))

    def test_public_disasm_defaults_to_entire_function_beyond_old_maximum(self):
        result = self.server.tools.methods['disasm']('0x1000', include_total=True)
        self.assertNotIn('error', result)
        self.assertEqual(result['instruction_count'], self.count)
        self.assertEqual(result['total_instructions'], self.count)
        self.assertEqual(result['cursor'], {'done': True})
        self.assertEqual(result['asm']['lines'][-1]['addr'], f'{self.func.end_ea - 4:x}')

    def test_explicit_code_pages_keep_exact_requested_contents_and_cursor(self):
        result = self.server.tools.methods['decompile']('0x1000', max_lines=3, offset=2)
        self.assertEqual(result['code'], '\n'.join(self.code.split('\n')[2:5]))
        self.assertEqual(result['line_count'], 3)
        self.assertEqual(result['cursor'], {'next': 5})
        result = self.server.tools.methods['disasm'](
            '0x1000', max_instructions=3, offset=5, include_total=True)
        self.assertEqual(result['instruction_count'], 3)
        self.assertEqual(result['total_instructions'], self.count)
        self.assertEqual(result['cursor'], {'next': 8})
        self.assertEqual(result['asm']['lines'][0]['addr'], f'{0x1000 + 5 * 4:x}')

    def test_batch_disassembly_and_blocks_are_not_silently_capped(self):
        analysis = self.modules['api_analysis']
        lines, truncated = analysis._disasm_lines_limited(self.func, 0)
        self.assertEqual(len(lines), self.count)
        self.assertFalse(truncated)
        blocks, truncated = analysis._collect_basic_blocks_limited(self.func, 0)
        self.assertEqual(len(blocks), self.block_count)
        self.assertFalse(truncated)

        # The public batch tool must select the unlimited default for each
        # section; helper-only checks cannot prove its default query behavior.
        utils = self.modules['utils']
        analysis.normalize_dict_list = utils.normalize_dict_list
        analysis.get_prototype = lambda func: 'void inert_function(void)'
        metadata = [{'addr': hex(i), 'value': i + 0x10000} for i in range(5001)]
        analysis.get_callees = lambda addr: metadata
        analysis.extract_function_strings = lambda ea: metadata
        analysis.extract_function_constants = lambda ea: metadata
        analysis.get_all_xrefs = lambda ea: {'to': metadata, 'from': metadata}
        result, = analysis.analyze_batch({'addr': '0x1000', 'include_disasm': True})
        self.assertIsNone(result['error'])
        batch = result['analysis']
        self.assertEqual(batch['decompile'], self.code)
        self.assertEqual(batch['disasm']['instruction_count'], self.count)
        self.assertFalse(batch['disasm']['truncated'])
        self.assertEqual(len(batch['basic_blocks']), self.block_count)
        self.assertFalse(batch['basic_blocks_truncated'])
        self.assertEqual(batch['caller_count'], 100)
        self.assertEqual(len(batch['callers']), 100)
        self.assertFalse(batch['callers_truncated'])
        for section in ('callees', 'strings', 'constants'):
            self.assertEqual(batch[section], metadata)
            self.assertFalse(batch[section + '_truncated'])
        self.assertEqual(batch['xrefs']['to'], metadata)
        self.assertEqual(batch['xrefs']['from'], metadata)
        self.assertFalse(batch['xrefs']['to_truncated'])
        self.assertFalse(batch['xrefs']['from_truncated'])

        # Explicit smaller selections must be marked as incomplete rather
        # than silently represented as full bodies/metadata.
        limited, = analysis.analyze_batch({
            'addr': '0x1000', 'include_disasm': True, 'max_disasm_insns': 300,
            'max_callers': 5, 'max_callees': 5, 'max_strings': 5,
            'max_constants': 5, 'max_blocks': 500,
        })
        batch = limited['analysis']
        self.assertEqual(batch['disasm']['instruction_count'], 300)
        self.assertTrue(batch['disasm']['truncated'])
        self.assertEqual(len(batch['basic_blocks']), 500)
        self.assertTrue(batch['basic_blocks_truncated'])
        for section in ('callers', 'callees', 'strings', 'constants'):
            self.assertEqual(len(batch[section]), 5)
            self.assertTrue(batch[section + '_truncated'])

    def test_caller_scan_crosses_iteration_guard_and_default_list_cap(self):
        utils = self.modules['utils']
        # The first 6000 resolvable references are not calls. Valid callers
        # appear after the old iteration guard and exceed the old default 50.
        callers = utils.get_callers('0x1000')
        self.assertEqual(len(callers), 100)
        self.assertEqual({row['addr'] for row in callers}, {hex(i) for i in range(6000, 6100)})
        for name in ('api_analysis', 'api_composite'):
            self.assertEqual(self.modules[name].get_callers('0x1000'), callers)


if __name__ == '__main__':
    unittest.main()
