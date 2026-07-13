"""DynDoris merge.

Corresponds to DynDorisMerge. Merge is Doris-aware: decrypt logical records,
filter obsolete versions/tombstones, and rebuild fresh encrypted runs. It never
concatenates old encrypted cells.
"""

from __future__ import annotations

import secrets
from typing import List, Optional, Sequence, Tuple

from .dyn_doris_run_builder import build_encrypted_run, decrypt_all_payloads
from .dyn_doris_server import DynDorisServer
from .dyn_doris_types import (
    ClientState,
    DocumentVersionRecord,
    DynDorisKeys,
    RunMeta,
    TombstoneRecord,
)


def merge_runs(
    *,
    state: ClientState,
    server: DynDorisServer,
    keys: DynDorisKeys,
    add_run_ids: Sequence[str],
    delete_run_ids: Sequence[str],
    current_time: int,
    epoch: int,
) -> Tuple[Optional[str], Optional[str]]:
    """Merge selected add/delete runs.

    Corresponds to DynDorisMerge step 1-11.
    """

    old_levels = [
        state.RunTbl[run_id].level for run_id in add_run_ids if run_id in state.RunTbl
    ] + [
        state.DelRunTbl[run_id].level
        for run_id in delete_run_ids
        if run_id in state.DelRunTbl
    ]
    # next_level: 新 run 放到被合并 run 的下一层。
    next_level = max(old_levels, default=-1) + 1

    # add_records: 从旧 add runs 解密恢复出的 logical document versions。
    add_records: List[DocumentVersionRecord] = []
    for run_id in add_run_ids:
        run = server.add_runs[run_id]
        for payload in decrypt_all_payloads(run, keys):
            assert payload.document is not None
            add_records.append(payload.document)

    # tombstones: 从旧 delete runs 解密恢复出的 logical delete records。
    tombstones: List[TombstoneRecord] = []
    for run_id in delete_run_ids:
        run = server.delete_runs[run_id]
        for payload in decrypt_all_payloads(run, keys):
            assert payload.tombstone is not None
            tombstones.append(payload.tombstone)

    # DynDorisMerge step 4-5.
    # dead_set: 本次 merge 内 tombstone 指向的旧 version ids。
    dead_set = {record.vid_old for record in tombstones}
    # live_records: 过滤掉已被 tombstone 废弃的 add records。
    live_records = [record for record in add_records if record.vid not in dead_set]

    # DynDorisMerge step 6. A tombstone can be dropped only if its target add run
    # is included in this merge. Otherwise the target may still be outside.
    # covered_add_runs: 本次 merge 覆盖到的 add runs。
    covered_add_runs = set(add_run_ids)
    # kept_tombstones: 目标 add run 不在本次 merge 中的 tombstone 需要继续保留。
    kept_tombstones = [
        record for record in tombstones if record.target_loc not in covered_add_runs
    ]

    # 删除旧 runs 后，用 logical records 重新 build fresh Doris runs。
    server.delete_runs_by_id(add_run_ids, delete_run_ids)
    for run_id in add_run_ids:
        state.RunTbl.pop(run_id, None)
    for run_id in delete_run_ids:
        state.DelRunTbl.pop(run_id, None)

    new_add_run_id = None
    if live_records:
        # fresh add run id 保证 merge 后不会复用旧 run key。
        new_add_run_id = _fresh_merge_run_id("rho", current_time)
        run = build_encrypted_run(
            run_id=new_add_run_id,
            run_type="add",
            records=live_records,
            keys=keys,
            level=next_level,
            created_at_update_time=current_time,
            epoch=epoch,
        )
        server.upload_run(run)
        state.RunTbl[new_add_run_id] = RunMeta(
            run_id=new_add_run_id,
            level=next_level,
            size=len(live_records),
            type="add",
            epoch=epoch,
            created_at_update_time=current_time,
        )
        for record in live_records:
            if record.id in state.DocState and state.DocState[record.id].vid == record.vid:
                state.DocState[record.id].loc = new_add_run_id
                record.loc = new_add_run_id

    new_delete_run_id = None
    if kept_tombstones:
        # 保留的 tombstones 也重新构建为 fresh delete run。
        new_delete_run_id = _fresh_merge_run_id("sigma", current_time)
        run = build_encrypted_run(
            run_id=new_delete_run_id,
            run_type="delete",
            records=kept_tombstones,
            keys=keys,
            level=next_level,
            created_at_update_time=current_time,
            epoch=epoch,
        )
        server.upload_run(run)
        state.DelRunTbl[new_delete_run_id] = RunMeta(
            run_id=new_delete_run_id,
            level=next_level,
            size=len(kept_tombstones),
            type="delete",
            epoch=epoch,
            created_at_update_time=current_time,
        )

    return new_add_run_id, new_delete_run_id


def _fresh_merge_run_id(prefix: str, current_time: int) -> str:
    return f"{prefix}_merge_{current_time}_{secrets.token_hex(8)}"
