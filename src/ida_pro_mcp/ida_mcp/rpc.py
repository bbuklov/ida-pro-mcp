import os
from typing import Any, Optional
from .zeromcp import (
    McpRpcRegistry,
    McpServer,
    McpToolError,
    McpHttpRequestHandler,
    get_current_request_external_base_url,
)

MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
MCP_SERVER = McpServer("ida-pro-mcp", extensions=MCP_EXTENSIONS)

# ============================================================================
# Complete tool output
# ============================================================================

_output_cache: dict[str, Any] = {}
_DOWNLOAD_BASE_URL_DEFAULT = "http://127.0.0.1:13337"


def configured_download_base_url() -> Optional[str]:
    """The public base URL the operator configured (#383), None if unset.

    The other IDA_MCP_* knobs (idalib_supervisor._env_float/_env_int,
    zeromcp._parse_bool_env) already treat a blank value as unset; so does the
    download base URL here so HTTP URL configuration stays consistent.
    """
    return os.environ.get("IDA_MCP_URL", "").strip() or None


_download_base_url: str = configured_download_base_url() or _DOWNLOAD_BASE_URL_DEFAULT


def set_download_base_url(url: str) -> None:
    global _download_base_url
    _download_base_url = url.rstrip("/")


def get_download_base_url() -> str:
    return get_current_request_external_base_url() or _download_base_url


def get_current_transport_session_id() -> str | None:
    return MCP_SERVER.get_current_transport_session_id()


def get_cached_output(output_id: str) -> Optional[Any]:
    return _output_cache.get(output_id)


def _limit_output_response(response: dict) -> dict:
    """Return the complete tool response, preserving its MCP envelope."""
    return response


# ============================================================================
# Decorators
# ============================================================================


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri):
    return MCP_SERVER.resource(uri)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


def ext(group: str):
    """Mark a tool as belonging to an extension group.

    Tools in extension groups are hidden by default. Enable via ?ext=group query param.
    Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
    """

    def decorator(func):
        if group not in MCP_EXTENSIONS:
            MCP_EXTENSIONS[group] = set()
        MCP_EXTENSIONS[group].add(func.__name__)
        return func

    return decorator


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_EXTENSIONS",
    "tool",
    "unsafe",
    "ext",
    "resource",
    "get_cached_output",
    "set_download_base_url",
    "get_download_base_url",
    "get_current_transport_session_id",
]
