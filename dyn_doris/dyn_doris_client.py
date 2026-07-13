"""DynDoris client.

Corresponds to DynDorisSetup, DynDorisSearchToken, ClientFilter, and update
entry points. Add/Delete/Flush/Merge are filled in separate steps.
"""

from __future__ import annotations

import secrets
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from Crypto.Random import get_random_bytes

from Utils.cryptoUtils import prf

from .dyn_doris_run_builder import (
    build_encrypted_run,
    decrypt_payload,
    make_search_token,
)
from .dyn_doris_merge import merge_runs
from .dyn_doris_server import DynDorisServer
from .dyn_doris_types import (
    ClientSearchResult,
    ClientState,
    DocumentVersionRecord,
    DynDorisKeys,
    MergePolicy,
    RunMeta,
    TombstoneRecord,
)


class DynDorisClient:
    """Functional DynDoris prototype client."""

    def __init__(
        self,
        *,
        buffer_capacity: int = 4,
        level_capacity: int = 2,
        server: Optional[DynDorisServer] = None,
    ) -> None:
        # keys: 客户端主密钥；服务器不持有这些密钥。
        self.keys = DynDorisKeys(
            K_master=get_random_bytes(16),
            K_vid=get_random_bytes(16),
        )
        # state: DynDorisSetup 输出的客户端状态。
        self.state = ClientState(MergePolicy=MergePolicy(level_capacity=level_capacity))
        # buffer_capacity: BufA/BufD 达到该容量时触发 flush。
        self.buffer_capacity = buffer_capacity
        # server: 只保存 encrypted runs 的内存服务器。
        self.server = server or DynDorisServer()
        # epoch: merge/rebuild generation。
        self.epoch = 0

    # Corresponds to DynDorisSetup step 2-7.
    def setup(self, db: Dict[str, Iterable[str]]) -> None:
        # initial: setup 阶段生成的 live document versions。
        initial: List[DocumentVersionRecord] = []
        for doc_id, keywords in db.items():
            W = set(keywords)
            if not W:
                continue
            vid = self._derive_vid(doc_id, 1)
            record = DocumentVersionRecord(
                id=doc_id,
                ver=1,
                W=W,
                tau=0,
                vid=vid,
                loc="pending",
            )
            initial.append(record)
            self.state.DocState[doc_id] = record

        for chunk in self._chunks(initial, self.buffer_capacity):
            # 每个 chunk 构建一个 fresh add run。
            run_id = self._fresh_run_id("rho")
            run = build_encrypted_run(
                run_id=run_id,
                run_type="add",
                records=chunk,
                keys=self.keys,
                level=0,
                created_at_update_time=self.state.t,
                epoch=self.epoch,
            )
            self.server.upload_run(run)
            self.state.RunTbl[run_id] = RunMeta(
                run_id=run_id,
                level=0,
                size=len(chunk),
                type="add",
                epoch=self.epoch,
                created_at_update_time=self.state.t,
            )
            for record in chunk:
                self.state.DocState[record.id].loc = run_id

    # Corresponds to DynDorisSearchToken and ServerSearch orchestration.
    def search(self, query: Sequence[str]) -> List[str]:
        return self.search_debug(query).ids

    def search_debug(self, query: Sequence[str]) -> ClientSearchResult:
        if not query:
            return ClientSearchResult([], 0, 0, 0)

        # 每个 add/delete run 都生成独立 token；server 不接收客户端状态表。
        add_tokens = [
            make_search_token(self.server.add_runs[run_id], query, self.keys)
            for run_id in self.state.RunTbl
        ]
        delete_tokens = [
            make_search_token(self.server.delete_runs[run_id], query, self.keys)
            for run_id in self.state.DelRunTbl
        ]
        server_result = self.server.search(add_tokens, delete_tokens)
        return self.client_filter(server_result.Cand, server_result.Dead)

    # Corresponds to ClientFilter step 1-5.
    def client_filter(self, cand: List[bytes], dead: List[bytes]) -> ClientSearchResult:
        # dead_set: 客户端解密 tombstone 后得到的旧 version ids。
        dead_set = set()
        for payload in dead:
            decoded = self._decrypt_payload_from_any_run(payload, "delete")
            assert decoded.tombstone is not None
            dead_set.add(decoded.tombstone.vid_old)

        # ans: doc id -> (ver, tau)，同一文档只保留最新 live version。
        ans: Dict[str, Tuple[int, int]] = {}
        killed_count = 0
        for payload in cand:
            decoded = self._decrypt_payload_from_any_run(payload, "add")
            assert decoded.document is not None
            record = decoded.document
            if record.vid in dead_set:
                killed_count += 1
                continue
            old = ans.get(record.id)
            if old is None or (record.ver, record.tau) > old:
                ans[record.id] = (record.ver, record.tau)

        return ClientSearchResult(
            ids=sorted(ans),
            candidate_count=len(cand),
            tombstone_count=len(dead),
            killed_count=killed_count,
        )

    # Corresponds to DynDorisUpdate(op, w, id).
    def update(self, op: str, w: str, doc_id: str) -> None:
        if op == "add":
            self.add(w, doc_id)
            return
        if op == "delete":
            self.delete(w, doc_id)
            return
        raise ValueError("op must be 'add' or 'delete'")

    # Corresponds to DynDorisAdd step 1-10.
    def add(self, w: str, doc_id: str) -> None:
        self.state.t += 1
        tau = self.state.t
        old = self.state.DocState.get(doc_id)

        if old and w in old.W:
            return

        W_old = set(old.W) if old else set()
        if old and W_old:
            # DynDorisAdd step 4: tombstone the old document version.
            # Add 不修改旧 encrypted entry，而是 tombstone 旧版本。
            self.state.BufD.append(
                TombstoneRecord(
                    vid_old=old.vid,
                    W_old=W_old,
                    tau_del=tau,
                    target_loc=old.loc,
                )
            )

        ver_new = old.ver + 1 if old else 1
        W_new = W_old | {w}
        vid_new = self._derive_vid(doc_id, ver_new)
        # new_record: 加入关键词后的新 document version，先进入 BufA。
        new_record = DocumentVersionRecord(
            id=doc_id,
            ver=ver_new,
            W=W_new,
            tau=tau,
            vid=vid_new,
            loc="BufA",
        )
        self.state.BufA.append(new_record)
        self.state.DocState[doc_id] = new_record
        self._maintenance()

    # Corresponds to DynDorisDelete step 1-10.
    def delete(self, w: str, doc_id: str) -> None:
        old = self.state.DocState.get(doc_id)
        if not old or w not in old.W:
            return

        self.state.t += 1
        tau = self.state.t
        W_old = set(old.W)

        # Security invariant: delete is not a public PRF(K, w || id) tag.
        # It tombstones the old document version.
        # Delete 不生成稳定公开删除标签，只记录被废弃的旧 vid。
        self.state.BufD.append(
            TombstoneRecord(
                vid_old=old.vid,
                W_old=W_old,
                tau_del=tau,
                target_loc=old.loc,
            )
        )

        W_new = W_old - {w}
        if not W_new:
            # 删除后 keyword set 为空，文档不再有 live version。
            self.state.DocState.pop(doc_id, None)
        else:
            ver_new = old.ver + 1
            vid_new = self._derive_vid(doc_id, ver_new)
            # 删除单个关键词后，剩余关键词形成新的 live version。
            new_record = DocumentVersionRecord(
                id=doc_id,
                ver=ver_new,
                W=W_new,
                tau=tau,
                vid=vid_new,
                loc="BufA",
            )
            self.state.BufA.append(new_record)
            self.state.DocState[doc_id] = new_record

        self._maintenance()

    # Corresponds to FlushAddBuffer step 1-7.
    def flush_add_buffer(self) -> Optional[str]:
        if not self.state.BufA:
            return None

        # records: 本次 flush 的 add buffer 快照。
        records = list(self.state.BufA)
        run_id = self._fresh_run_id("rho")
        run = build_encrypted_run(
            run_id=run_id,
            run_type="add",
            records=records,
            keys=self.keys,
            level=0,
            created_at_update_time=self.state.t,
            epoch=self.epoch,
        )
        self.server.upload_run(run)
        self.state.RunTbl[run_id] = RunMeta(
            run_id=run_id,
            level=0,
            size=len(records),
            type="add",
            epoch=self.epoch,
            created_at_update_time=self.state.t,
        )
        for record in records:
            if record.id in self.state.DocState and self.state.DocState[record.id].vid == record.vid:
                self.state.DocState[record.id].loc = run_id
                record.loc = run_id
        self.state.BufA.clear()
        return run_id

    # Corresponds to FlushDeleteBuffer step 1-6.
    def flush_delete_buffer(self) -> Optional[str]:
        if not self.state.BufD:
            return None

        # records: 本次 flush 的 delete buffer 快照。
        records = list(self.state.BufD)
        run_id = self._fresh_run_id("sigma")
        run = build_encrypted_run(
            run_id=run_id,
            run_type="delete",
            records=records,
            keys=self.keys,
            level=0,
            created_at_update_time=self.state.t,
            epoch=self.epoch,
        )
        self.server.upload_run(run)
        self.state.DelRunTbl[run_id] = RunMeta(
            run_id=run_id,
            level=0,
            size=len(records),
            type="delete",
            epoch=self.epoch,
            created_at_update_time=self.state.t,
        )
        self.state.BufD.clear()
        return run_id

    # Corresponds to DynDorisMerge step 1-11.
    def merge(
        self,
        add_run_ids: Sequence[str],
        delete_run_ids: Sequence[str],
    ) -> Tuple[Optional[str], Optional[str]]:
        self.epoch += 1
        return merge_runs(
            state=self.state,
            server=self.server,
            keys=self.keys,
            add_run_ids=add_run_ids,
            delete_run_ids=delete_run_ids,
            current_time=self.state.t,
            epoch=self.epoch,
        )

    def _decrypt_payload_from_any_run(self, payload: bytes, expected_type: str):
        runs = self.server.add_runs if expected_type == "add" else self.server.delete_runs
        for run in runs.values():
            try:
                decoded = decrypt_payload(run, payload, self.keys)
            except Exception:
                continue
            if decoded.record_type == expected_type:
                return decoded
        raise ValueError("payload does not belong to any known run")

    def _maintenance(self) -> None:
        # 简单维护策略：buffer 满时立即 flush；自动 merge 暂未实现。
        if len(self.state.BufA) >= self.buffer_capacity:
            self.flush_add_buffer()
        if len(self.state.BufD) >= self.buffer_capacity:
            self.flush_delete_buffer()

    def _derive_vid(self, doc_id: str, ver: int) -> bytes:
        return prf(self.keys.K_vid, "vid|" + doc_id + "|" + str(ver))

    def _fresh_run_id(self, prefix: str) -> str:
        return f"{prefix}_{self.state.t}_{secrets.token_hex(8)}"

    @staticmethod
    def _chunks(items: List[DocumentVersionRecord], size: int):
        for i in range(0, len(items), size):
            yield items[i : i + size]
