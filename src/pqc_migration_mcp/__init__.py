"""MCP server exposing post-quantum migration analysis to AI agents."""

from .server import TOOLS, handle, serve

__version__ = "0.1.0"
__all__ = ["TOOLS", "__version__", "handle", "serve"]
