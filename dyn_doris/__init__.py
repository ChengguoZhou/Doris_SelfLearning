"""DynDoris prototype package.

This package is intentionally separate from the original Doris implementation.
It reuses Doris utility structures through small wrappers instead of rewriting
or modifying the original files.
"""

from .dyn_doris_client import DynDorisClient
from .dyn_doris_types import (
    ClientState,
    DocumentVersionRecord,
    EncryptedRun,
    RunMeta,
    TombstoneRecord,
)

__all__ = [
    "ClientState",
    "DocumentVersionRecord",
    "DynDorisClient",
    "EncryptedRun",
    "RunMeta",
    "TombstoneRecord",
]
