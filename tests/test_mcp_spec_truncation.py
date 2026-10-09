"""Complete-output MCP envelope and schema regressions for this fork."""

import importlib
import json
import os
import sys
import pathlib
import unittest
from typing import TypedDict
from unittest import mock

from jsonschema import Draft202012Validator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import (
    CALL_TOOL_RESULT_SCHEMA,
    McpHttpTestServer,
    McpServer,
    assert_schema,
    call_rpc,
    load_ida_rpc_module,
)


class _Item(TypedDict):
    name: str
    value: int


class _ListResult(TypedDict):
    items: list[_Item]
    count: int


def _fresh_full_output_server() -> McpServer:
    """Use the production RPC module's server without extra middleware."""
    return load_ida_rpc_module().MCP_SERVER


class FullOutputInvariantTests(unittest.TestCase):
    def _call_large_list_tool(self, srv):
        @srv.tool
        def big_list() -> _ListResult:
            """Return a list larger than the former response preview."""
            return {
                "items": [{"name": f"n{i}", "value": i} for i in range(5000)],
                "count": 5000,
            }

        tools = call_rpc(srv, "tools/list")["tools"]
        tool = next(t for t in tools if t["name"] == "big_list")
        result = call_rpc(srv, "tools/call", name="big_list", arguments={})
        return tool, result

    def test_large_output_is_complete(self):
        srv = _fresh_full_output_server()
        _, result = self._call_large_list_tool(srv)
        data = result["structuredContent"]
        self.assertEqual(len(data["items"]), data["count"])
        self.assertEqual(data["items"][-1], {"name": "n4999", "value": 4999})
        self.assertEqual(json.loads(result["content"][0]["text"]), data)
        self.assertNotIn("_meta", result)

    def test_full_structuredContent_matches_outputSchema(self):
        srv = _fresh_full_output_server()
        tool, result = self._call_large_list_tool(srv)
        Draft202012Validator(tool["outputSchema"]).validate(result["structuredContent"])

    def test_full_response_envelope_is_valid_call_tool_result(self):
        srv = _fresh_full_output_server()
        _, result = self._call_large_list_tool(srv)
        assert_schema(result, CALL_TOOL_RESULT_SCHEMA)

    def test_response_fields_remain_schema_valid(self):
        # Regression for #361: underscore-prefixed fields must not leak.
        srv = _fresh_full_output_server()
        _, result = self._call_large_list_tool(srv)
        leaked = [k for k in result["structuredContent"] if k.startswith("_")]
        self.assertFalse(leaked, f"leaked keys: {leaked}")

    def test_full_items_do_not_contain_sentinel_dict(self):
        # Regression for e802b32: no {"_truncated": ...} appended to lists.
        srv = _fresh_full_output_server()
        _, result = self._call_large_list_tool(srv)
        for item in result["structuredContent"].get("items", []):
            with self.subTest(item=item):
                self.assertEqual(set(item.keys()), {"name", "value"})

    def test_large_output_needs_no_download_hint(self):
        srv = _fresh_full_output_server()
        _, result = self._call_large_list_tool(srv)
        self.assertNotIn("ida_mcp", result.get("_meta", {}))
        self.assertEqual(len(result["content"]), 1)

    def test_content_text_blocks_are_valid(self):
        srv = _fresh_full_output_server()
        _, result = self._call_large_list_tool(srv)
        self.assertGreaterEqual(len(result["content"]), 1)
        for block in result["content"]:
            with self.subTest(block=block):
                self.assertEqual(block["type"], "text")
                self.assertIsInstance(block["text"], str)

    def test_many_large_fields_are_preserved(self):
        class ManyStrings(TypedDict):
            fields: dict[str, str]

        srv = _fresh_full_output_server()

        @srv.tool
        def many_strings() -> ManyStrings:
            """Returns many independently large string fields."""
            return {"fields": {f"field_{i}": "x" * 10000 for i in range(20)}}

        result = call_rpc(srv, "tools/call", name="many_strings", arguments={})
        data = result["structuredContent"]
        self.assertEqual(len(data["fields"]), 20)
        self.assertTrue(all(value == "x" * 10000 for value in data["fields"].values()))


class FullOutputOverHttpTests(unittest.TestCase):
    def test_forwarded_public_base_does_not_change_complete_output(self):
        srv = _fresh_full_output_server()

        @srv.tool
        def big_list() -> _ListResult:
            """Return a list larger than the former response preview."""
            return {
                "items": [{"name": f"n{i}", "value": i} for i in range(5000)],
                "count": 5000,
            }

        with McpHttpTestServer(srv) as harness:
            status, _, response = harness.post_jsonrpc(
                "tools/call",
                {"name": "big_list", "arguments": {}},
                extra_headers={
                    "Forwarded": 'for=127.0.0.1;proto=https;host="mcp.example.com"',
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(len(response["result"]["structuredContent"]["items"]), 5000)
        self.assertNotIn("_meta", response["result"])

    def test_forwarded_prefix_does_not_change_complete_output(self):
        srv = _fresh_full_output_server()

        @srv.tool
        def big_list() -> _ListResult:
            """Return a list larger than the former response preview."""
            return {
                "items": [{"name": f"n{i}", "value": i} for i in range(5000)],
                "count": 5000,
            }

        with McpHttpTestServer(srv) as harness:
            status, _, response = harness.post_jsonrpc(
                "tools/call",
                {"name": "big_list", "arguments": {}},
                extra_headers={
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "mcp.example.com",
                    "X-Forwarded-Prefix": "/ida/proxy/",
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(len(response["result"]["structuredContent"]["items"]), 5000)
        self.assertNotIn("_meta", response["result"])


class NonTruncatedOutputsUnchangedTests(unittest.TestCase):
    def test_small_output_has_no_truncation_metadata(self):
        srv = _fresh_full_output_server()

        @srv.tool
        def small() -> _ListResult:
            """small list."""
            return {"items": [{"name": "n", "value": 1}], "count": 1}

        result = call_rpc(srv, "tools/call", name="small", arguments={})
        self.assertNotIn("ida_mcp", result.get("_meta") or {})

    def test_small_output_structuredContent_is_exact(self):
        srv = _fresh_full_output_server()

        @srv.tool
        def small() -> _ListResult:
            """small list."""
            return {"items": [{"name": "n", "value": 1}], "count": 1}

        result = call_rpc(srv, "tools/call", name="small", arguments={})
        self.assertEqual(
            result["structuredContent"],
            {"items": [{"name": "n", "value": 1}], "count": 1},
        )


class CompleteDeeplyNestedDataTests(unittest.TestCase):
    def test_nested_dict_output_still_schema_valid(self):
        class Deep(TypedDict):
            label: str
            value: str

        class Outer(TypedDict):
            levels: dict[str, Deep]

        srv = _fresh_full_output_server()

        @srv.tool
        def deep() -> Outer:
            """deep nested."""
            return {
                "levels": {f"k{i}": {"label": f"l{i}", "value": "v" * 200} for i in range(200)}
            }

        tools = call_rpc(srv, "tools/list")["tools"]
        tool = next(t for t in tools if t["name"] == "deep")
        result = call_rpc(srv, "tools/call", name="deep", arguments={})
        Draft202012Validator(tool["outputSchema"]).validate(result["structuredContent"])


class DownloadBaseUrlFromEnvTests(unittest.TestCase):
    """`IDA_MCP_URL` is the operator's public base URL for downloads (#383)."""

    @staticmethod
    def _reload_rpc_with_url(value: str | None):
        """Re-evaluate rpc.py with IDA_MCP_URL set to `value` (None: unset)."""
        rpc = load_ida_rpc_module()
        with mock.patch.dict(os.environ, clear=True):
            if value is not None:
                os.environ["IDA_MCP_URL"] = value
            importlib.reload(rpc)
        return rpc

    def tearDown(self):
        importlib.reload(load_ida_rpc_module())

    def test_blank_url_falls_back_to_the_default_base(self):
        for value in ["", "   ", None]:
            with self.subTest(IDA_MCP_URL=value):
                rpc = self._reload_rpc_with_url(value)
                self.assertEqual(
                    rpc.get_download_base_url(),
                    "http://127.0.0.1:13337",
                )

    def test_configured_url_is_used_verbatim_once_stripped(self):
        rpc = self._reload_rpc_with_url("  https://mcp.example.com/ida ")
        self.assertEqual(
            rpc.get_download_base_url(),
            "https://mcp.example.com/ida",
        )

    def test_complete_output_does_not_need_a_download_url(self):
        self._reload_rpc_with_url("")
        srv = _fresh_full_output_server()

        @srv.tool
        def big_list() -> _ListResult:
            """Return a list larger than the former response preview."""
            return {
                "items": [{"name": f"n{i}", "value": i} for i in range(5000)],
                "count": 5000,
            }

        result = call_rpc(srv, "tools/call", name="big_list", arguments={})
        self.assertNotIn("_meta", result)
        self.assertEqual(len(result["structuredContent"]["items"]), 5000)


if __name__ == "__main__":
    unittest.main()
