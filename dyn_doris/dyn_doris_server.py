"""DynDoris in-memory server.

Corresponds to ServerSearch. The server stores encrypted runs and returns Cand
and Dead without applying tombstones to candidates.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

from .dyn_doris_run_builder import search_encrypted_run
from .dyn_doris_types import EncryptedRun, SearchToken, ServerSearchResult


class DynDorisServer:
    """In-memory encrypted run store."""

    def __init__(self) -> None:
        self.add_runs: Dict[str, EncryptedRun] = {}
        self.delete_runs: Dict[str, EncryptedRun] = {}

    def upload_run(self, run: EncryptedRun) -> None:
        if run.run_type == "add":
            self.add_runs[run.run_id] = run
        elif run.run_type == "delete":
            self.delete_runs[run.run_id] = run
        else:
            raise ValueError(f"unknown run type: {run.run_type!r}")

    def delete_runs_by_id(self, add_run_ids: Iterable[str], delete_run_ids: Iterable[str]) -> None:
        for run_id in add_run_ids:
            self.add_runs.pop(run_id, None)
        for run_id in delete_run_ids:
            self.delete_runs.pop(run_id, None)

    def get_run(self, run_id: str) -> EncryptedRun:
        if run_id in self.add_runs:
            return self.add_runs[run_id]
        if run_id in self.delete_runs:
            return self.delete_runs[run_id]
        raise KeyError(run_id)

    # Corresponds to ServerSearch step 3-5.
    def search(self, add_tokens: List[SearchToken], delete_tokens: List[SearchToken]) -> ServerSearchResult:
        cand: List[bytes] = []
        dead: List[bytes] = []

        for token in add_tokens:
            cand.extend(search_encrypted_run(self.add_runs[token.run_id], token))
        for token in delete_tokens:
            dead.extend(search_encrypted_run(self.delete_runs[token.run_id], token))

        # Security invariant: no server-side candidate deletion is performed.
        return ServerSearchResult(Cand=cand, Dead=dead)
