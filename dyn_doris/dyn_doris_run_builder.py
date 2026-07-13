"""DynDoris run builder and Doris wrapper.

Corresponds to BuildDorisRun, BuildTombstoneDorisRun, DorisSearch, and the
run-local encrypted structure used by DynDorisSetup/Search/Flush/Merge.
"""

from __future__ import annotations

import pickle
import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Set

from Utils.SSPE_XF import SSPE_XF
from Utils.TSet import TSet, genStag
from Utils.cryptoUtils import AES_dec, AES_enc, prf

from .dyn_doris_types import (
    DecryptedPayload,
    DocumentVersionRecord,
    DynDorisKeys,
    EncryptedRun,
    RunType,
    SearchToken,
    TombstoneRecord,
)


sspe = SSPE_XF()


@dataclass(frozen=True)
class RunKeys:
    """Fresh run-local keys derived from K_master and a fresh run id."""

    # K_t: 预留给 TSet 的 run-local key；当前 TSet.setup 内部自行生成 key
    K_t: bytes
    # K_x: 派生 run-local XSet tags 的 key
    K_x: bytes
    # K_e: 加密 logical record payload 的 AES key
    K_e: bytes
    # run_key_id: 用于测试 fresh key 是否变化的辅助标识
    run_key_id: bytes


def derive_run_keys(keys: DynDorisKeys, run_id: str, run_type: RunType) -> RunKeys:
    """Derive run-local keys; fresh run ids imply fresh run keys.

    Corresponds to DynDorisSetup step 5 and FlushAdd/Delete step 2.
    """

    seed = prf(keys.K_master, b"run-key|" + run_type.encode() + b"|" + run_id.encode())
    return RunKeys(
        K_t=prf(seed, "tset"),
        K_x=prf(seed, "xset"),
        K_e=prf(seed, "payload")[:16],
        run_key_id=prf(seed, "run-key-id"),
    )


def record_keywords(record: object) -> Set[str]:
    # add record 使用当前版本 W；delete record 使用旧版本 W_old。
    if isinstance(record, DocumentVersionRecord):
        return set(record.W)
    if isinstance(record, TombstoneRecord):
        return set(record.W_old)
    raise TypeError(f"unsupported DynDoris record type: {type(record)!r}")


def _payload(run_type: RunType, record: object) -> bytes:
    # payload 中保留 record 类型，客户端解密后可恢复强类型对象。
    return pickle.dumps({"record_type": run_type, "record": record})


def decrypt_payload(run: EncryptedRun, payload: bytes, keys: DynDorisKeys) -> DecryptedPayload:
    """Client-side payload decryption."""

    # 只有客户端持有 keys，可以根据 run id/type 重新派生 payload key。
    run_keys = derive_run_keys(keys, run.run_id, run.run_type)
    data = pickle.loads(AES_dec(run_keys.K_e, payload))
    record_type = data["record_type"]
    record = data["record"]
    if record_type == "add":
        return DecryptedPayload(record_type="add", document=record)
    if record_type == "delete":
        return DecryptedPayload(record_type="delete", tombstone=record)
    raise ValueError(f"unknown payload record_type: {record_type!r}")


def build_encrypted_run(
    *,
    run_id: str,
    run_type: RunType,
    records: Sequence[object],
    keys: DynDorisKeys,
    level: int,
    created_at_update_time: int,
    epoch: int = 0,
    tset_k: int = 2,
) -> EncryptedRun:
    """Build a fresh immutable run from logical records.

    Corresponds to BuildDorisRun:
    1. Build a TSet posting list for each keyword.
    2. Build run-local S2PE/XSet encoding with SSPE_XF/XorFilter.
    3. Store only encrypted payloads for version/tombstone records.

    Merge callers must pass logical records and rebuild; old encrypted cells are
    intentionally not accepted here.
    """

    assert records, "cannot build an empty encrypted run"

    run_keys = derive_run_keys(keys, run_id, run_type)
    # postings: TSet posting list，keyword -> handles。
    postings: Dict[str, List[bytes]] = {}
    # xset: run-local 合取标签集合，用于 DorisSearch 过滤非 s-term 关键词。
    xset: Set[bytes] = set()
    # positions: 每个 keyword 在 posting list 中的本地位置计数。
    positions: Dict[str, int] = {}
    # encrypted_payloads: handle -> Enc(K_e, logical record)。
    encrypted_payloads: Dict[bytes, bytes] = {}

    for record in records:
        # handle 是服务器可见的随机索引柄，不暴露文档 id/version。
        handle = secrets.token_bytes(16)
        encrypted_payloads[handle] = AES_enc(run_keys.K_e, _payload(run_type, record))
        keywords = sorted(record_keywords(record))

        for w in keywords:
            positions[w] = positions.get(w, 0) + 1
            i = positions[w]
            postings.setdefault(w, []).append(handle)
            for x in keywords:
                if x != w:
                    xset.add(prf(run_keys.K_x, w + "|" + x + "|" + str(i)))

    total_postings = max(sum(len(v) for v in postings.values()), 1)
    last_error = None
    tset = None
    for grow in (1, 2, 4, 8, 16, 32):
        try:
            tset = TSet(total_postings * grow, tset_k)
            # TSet.setup normally creates kt internally. We provide run-local kt
            # by setting the field after setup would not work, so this prototype
            # builds the same structure with the existing TSet API by monkey
            # using its internal hash path through deterministic precomputed stag
            # is not supported. Therefore tset_key is the kt returned by setup.
            # Freshness still holds because every run is rebuilt from scratch.
            tset_key = tset.setup(postings)
            break
        except Exception as exc:
            last_error = exc
            if "insufficient space" not in str(exc):
                raise
    else:
        raise RuntimeError("failed to build TSet") from last_error

    xset_msk_xf = sspe.setup(max(len(xset), 1))
    if xset:
        sspe.enc(xset_msk_xf, list(xset))

    return EncryptedRun(
        run_id=run_id,
        run_type=run_type,
        level=level,
        created_at_update_time=created_at_update_time,
        epoch=epoch,
        tset=tset,
        tset_key=tset_key,
        xset_ciphertext=xset_msk_xf.xf,
        xset_msk=xset_msk_xf.msk,
        encrypted_payloads=encrypted_payloads,
        run_key_id=run_keys.run_key_id,
    )


def make_search_token(run: EncryptedRun, query: Sequence[str], keys: DynDorisKeys) -> SearchToken:
    """Create a per-run search token.

    Corresponds to DynDorisSearchToken step 2-3. The current SelectSTerm policy
    is Q[0].
    """

    assert query, "query must not be empty"
    # SelectSTerm(Q): 当前原型固定选择 Q[0] 作为 s-term。
    s_term = query[0]
    run_keys = derive_run_keys(keys, run.run_id, run.run_type)
    # stag 用于从当前 run 的 TSet 中取出 s-term posting list。
    stag = genStag(run.tset_key, s_term)
    handles = run.tset.retrive(stag)
    xtokens: List[object] = []

    if len(query) > 1:
        for i in range(len(handles)):
            qtags = [
                prf(run_keys.K_x, s_term + "|" + x + "|" + str(i + 1))
                for x in query[1:]
            ]
            xtokens.append(sspe.keyGen(run.xset_msk, qtags))

    return SearchToken(
        run_id=run.run_id,
        run_type=run.run_type,
        stag=stag,
        xtokens=xtokens,
        query_len=len(query),
    )


def search_encrypted_run(run: EncryptedRun, token: SearchToken) -> List[bytes]:
    """Server-side DorisSearch over one run.

    The server returns encrypted payloads only. It must not decrypt payloads or
    match tombstones against candidates.
    """

    assert token.run_id == run.run_id
    # server 只能拿到 handles 并返回加密 payload，不知道 payload 的语义。
    handles = run.tset.retrive(token.stag)
    result: List[bytes] = []
    for i, handle in enumerate(handles):
        if token.query_len == 1 or sspe.dec(token.xtokens[i], run.xset_ciphertext):
            result.append(run.encrypted_payloads[bytes(handle)])
    return result


def decrypt_all_payloads(run: EncryptedRun, keys: DynDorisKeys) -> List[DecryptedPayload]:
    """Client-side helper for merge: decrypt logical records before rebuilding."""

    return [
        decrypt_payload(run, payload, keys)
        for payload in run.encrypted_payloads.values()
    ]


def live_ids_from_records(records: Iterable[DocumentVersionRecord]) -> Set[str]:
    return {record.id for record in records}
