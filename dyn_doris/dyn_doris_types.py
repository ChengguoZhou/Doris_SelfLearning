"""DynDoris data types.

Corresponds to DynDorisSetup state, run metadata, document version records,
and tombstone records in the DynDoris pseudocode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Set


RunType = Literal["add", "delete"]
# RunType: run 的逻辑类型，add run 保存文档版本，delete run 保存 tombstone


@dataclass
class DocumentVersionRecord:
    """Logical add record: (id, ver, W, tau, vid, loc)."""
    # id: 文档 id
    id: str
    # ver: 文档版本号
    ver: int
    # W: 当前版本 keyword set
    W: Set[str]
    # tau: 创建该版本的更新时间
    tau: int
    # vid: version id，用于 tombstone 精确废弃旧版本
    vid: bytes
    # loc: 当前版本所在位置：`pending`, `BufA`, 或 add run id
    loc: str = "pending"


@dataclass
class TombstoneRecord:
    """Logical delete record: (vid_old, W_old, tau_del, target_loc)."""
    # vid_old: 被废弃旧版本的 version id
    vid_old: bytes
    # W_old: 旧版本 keyword set，使 tombstone 也可按合取查询过滤
    W_old: Set[str]
    # tau_del: 删除发生的更新时间
    tau_del: int
    # target_loc: 旧版本所在位置，用于 merge 判断 tombstone 是否可丢弃
    target_loc: str


@dataclass
class RunMeta:
    """Client metadata for one immutable add/delete run."""
    # run_id: fresh run id
    run_id: str
    # level: merge 层级
    level: int
    # size: run 中 logical records 数量
    size: int
    # type: add/delete
    type: RunType
    # epoch: rebuild generation，merge 重建代数
    epoch: int = 0
    # created_at_update_time: 创建 run 时的更新时间 t
    created_at_update_time: int = 0


@dataclass
class MergePolicy:
    """Small leveled merge policy for the prototype."""

    # level_capacity: 每层允许保留的 run 数量上限，当前原型只保存策略参数
    level_capacity: int = 2


@dataclass
class ClientState:
    """Client state: (t, RunTbl, DelRunTbl, BufA, BufD, DocState, MergePolicy)."""
    # t: 全局更新时间
    t: int = 0
    # RunTbl: add run metadata，客户端保存 add run 的元数据表
    RunTbl: Dict[str, RunMeta] = field(default_factory=dict)
    # DelRunTbl: delete run metadata，客户端保存 delete run 的元数据表
    DelRunTbl: Dict[str, RunMeta] = field(default_factory=dict)
    # BufA: add buffer，暂存新的 DocumentVersionRecord
    BufA: List[DocumentVersionRecord] = field(default_factory=list)
    # BufD: delete buffer，暂存新的 TombstoneRecord
    BufD: List[TombstoneRecord] = field(default_factory=list)
    # DocState: 每个文档当前 live version
    DocState: Dict[str, DocumentVersionRecord] = field(default_factory=dict)
    # MergePolicy: 当前简单 merge policy
    MergePolicy: MergePolicy = field(default_factory=MergePolicy)


@dataclass
class SearchToken:
    """Per-run search token sent to the server."""

    # run_id: token 对应的目标 run id
    run_id: str
    # run_type: token 对应 add run 或 delete run
    run_type: RunType
    # stag: TSet 查询标签，由 s-term 和 tset_key 生成
    stag: bytes
    # xtokens: 合取过滤 token，用于检查 s-term 之外的关键词
    xtokens: List[object]
    # query_len: 查询关键词数量，单关键词查询不需要 xtokens
    query_len: int


@dataclass
class ServerSearchResult:
    """Server output. The server must not match Dead against Cand."""

    # Cand: add run 返回的加密 candidate payloads
    Cand: List[bytes] = field(default_factory=list)
    # Dead: delete run 返回的加密 tombstone payloads
    Dead: List[bytes] = field(default_factory=list)


@dataclass
class ClientSearchResult:
    """Debuggable client-side filter output."""

    # ids: 客户端过滤后返回的 live document ids
    ids: List[str]
    # candidate_count: 服务器返回的 Cand 数量
    candidate_count: int
    # tombstone_count: 服务器返回的 Dead 数量
    tombstone_count: int
    # killed_count: 被 tombstone 过滤掉的 candidate 数量
    killed_count: int


@dataclass
class EncryptedRun:
    """DorisRunWrapper/EncryptedRun wrapper for a run-local encrypted index."""
    # run_id: run id
    run_id: str
    # run_type: add/delete
    run_type: RunType
    # level: merge 层级
    level: int
    # created_at_update_time: 创建 run 时的更新时间 t
    created_at_update_time: int
    # epoch: rebuild generation
    epoch: int
    # tset: Doris TSet 结构
    tset: object
    # tset_key: TSet.setup 返回的 key
    tset_key: bytes
    # xset_ciphertext: SSPE/XorFilter ciphertext
    xset_ciphertext: object
    # xset_msk: 生成查询 token 需要的 msk
    xset_msk: object
    # encrypted_payloads: handle -> encrypted payload
    encrypted_payloads: Dict[bytes, bytes]
    # run_key_id: 测试 fresh key 的辅助标识
    run_key_id: bytes


@dataclass
class DynDorisKeys:
    """Client master keys for run-key and vid derivation."""

    # K_master: 派生 run-local keys 的客户端主密钥
    K_master: bytes
    # K_vid: 派生 document version id 的客户端密钥
    K_vid: bytes


@dataclass
class DecryptedPayload:
    """Typed payload recovered by the client."""

    # record_type: payload 原始类型，add 或 delete
    record_type: RunType
    # document: 解密出的 DocumentVersionRecord，仅 add payload 使用
    document: Optional[DocumentVersionRecord] = None
    # tombstone: 解密出的 TombstoneRecord，仅 delete payload 使用
    tombstone: Optional[TombstoneRecord] = None
