"""DynDoris benchmark adapter.

Corresponds to the future benchmark-loading layer. This file intentionally
keeps benchmarking separate from correctness tests and original Doris scripts.
"""

from __future__ import annotations

from time import perf_counter
from typing import Dict, Iterable, List, Sequence

from Utils.fileUtils import read_index

from .dyn_doris_client import DynDorisClient


def load_doc_keywords_from_index(path: str) -> Dict[str, List[str]]:
    """Load id -> keyword_set data for DynDorisSetup."""

    return read_index(path)


def run_small_benchmark(
    doc_keywords: Dict[str, Iterable[str]],
    query: Sequence[str],
    *,
    buffer_capacity: int = 16,
) -> Dict[str, object]:
    """Minimal benchmark helper for later integration with real experiments."""

    client = DynDorisClient(buffer_capacity=buffer_capacity)

    start = perf_counter()
    client.setup(doc_keywords)
    setup_s = perf_counter() - start

    start = perf_counter()
    result = client.search(query)
    search_s = perf_counter() - start

    return {
        "docs": len(doc_keywords),
        "query": " ".join(query),
        "matches": len(result),
        "setup_s": round(setup_s, 6),
        "search_s": round(search_s, 6),
        "add_runs": len(client.state.RunTbl),
        "delete_runs": len(client.state.DelRunTbl),
    }
