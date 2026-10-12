"""Framework-neutral AHP handlers and optional ASGI/AnyIO transports.

``serve`` is the AnyIO stdio server (``agenthooksprotocol.server.stdio.serve``).
Import other transports explicitly: ``from agenthooksprotocol.server import asgi``.
"""

from . import hooks
from .stdio import serve

__all__ = ["hooks", "serve"]
