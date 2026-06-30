"""DynDoris data types.

Corresponds to DynDorisSetup state, run metadata, document version records,
and tombstone records in the DynDoris pseudocode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Set


RunType = Literal["add", "delete"]


@dataclass
class DocumentVersionRecord:
    """Logical add record: (id, ver, W, tau, vid, loc)."""

    id: str
    ver: int
    W: Set[str]
    tau: int
    vid: bytes
    loc: str = "pending"


@dataclass
class TombstoneRecord:
    """Logical delete record: (vid_old, W_old, tau_del, target_loc)."""

    vid_old: bytes
    W_old: Set[str]
    tau_del: int
    target_loc: str


@dataclass
class RunMeta:
    """Client metadata for one immutable add/delete run."""

    run_id: str
    level: int
    size: int
    type: RunType
    epoch: int = 0
    created_at_update_time: int = 0


@dataclass
class MergePolicy:
    """Small leveled merge policy for the prototype."""

    level_capacity: int = 2


@dataclass
class ClientState:
    """Client state: (t, RunTbl, DelRunTbl, BufA, BufD, DocState, MergePolicy)."""

    t: int = 0
    RunTbl: Dict[str, RunMeta] = field(default_factory=dict)
    DelRunTbl: Dict[str, RunMeta] = field(default_factory=dict)
    BufA: List[DocumentVersionRecord] = field(default_factory=list)
    BufD: List[TombstoneRecord] = field(default_factory=list)
    DocState: Dict[str, DocumentVersionRecord] = field(default_factory=dict)
    MergePolicy: MergePolicy = field(default_factory=MergePolicy)


@dataclass
class SearchToken:
    """Per-run search token sent to the server."""

    run_id: str
    run_type: RunType
    stag: bytes
    xtokens: List[object]
    query_len: int


@dataclass
class ServerSearchResult:
    """Server output. The server must not match Dead against Cand."""

    Cand: List[bytes] = field(default_factory=list)
    Dead: List[bytes] = field(default_factory=list)


@dataclass
class ClientSearchResult:
    """Debuggable client-side filter output."""

    ids: List[str]
    candidate_count: int
    tombstone_count: int
    killed_count: int


@dataclass
class EncryptedRun:
    """DorisRunWrapper/EncryptedRun wrapper for a run-local encrypted index."""

    run_id: str
    run_type: RunType
    level: int
    created_at_update_time: int
    epoch: int
    tset: object
    tset_key: bytes
    xset_ciphertext: object
    xset_msk: object
    encrypted_payloads: Dict[bytes, bytes]
    run_key_id: bytes


@dataclass
class DynDorisKeys:
    """Client master keys for run-key and vid derivation."""

    K_master: bytes
    K_vid: bytes


@dataclass
class DecryptedPayload:
    """Typed payload recovered by the client."""

    record_type: RunType
    document: Optional[DocumentVersionRecord] = None
    tombstone: Optional[TombstoneRecord] = None
