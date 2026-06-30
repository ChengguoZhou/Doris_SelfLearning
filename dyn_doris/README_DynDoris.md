# DynDoris Prototype

This directory contains a minimal DynDoris prototype built next to the original
Doris code. It does not modify `Doris_XF.py` or the `Utils/` primitives.

## Build / Install

No compilation is required. Use the same Python environment as the original
Doris project.

```bash
pip install -r requirements.txt
```

## Run Correctness Tests

```bash
python -m unittest discover -s dyn_doris/tests
```

## Implemented Algorithms

- `DynDorisSetup`: `DynDorisClient.setup`
- `DynDorisSearch`: `DynDorisClient.search`
- `DynDorisUpdate(op, w, id)`: `DynDorisClient.update`
- `FlushAddBuffer`: `DynDorisClient.flush_add_buffer`
- `FlushDeleteBuffer`: `DynDorisClient.flush_delete_buffer`
- `DynDorisMerge`: `dyn_doris_merge.merge_runs`

## Reused Doris Components

- `Utils.TSet.TSet` and `Utils.TSet.genStag`
- `Utils.SSPE_XF.SSPE_XF`
- `Utils.cryptoUtils.prf`, `AES_enc`, `AES_dec`
- `Utils.fileUtils.read_index` for benchmark loading

## Real Mode and Toy Mode

The default implementation is `real` mode and reuses Doris `TSet` plus
`SSPE_XF`/XorFilter for each immutable run.

`toy` mode is intentionally not implemented in this first prototype. If added
later, it must be named explicitly and must not be used for security evaluation.

## Security Invariants Captured in Code

- The server returns only `Cand` and `Dead`.
- The server never removes candidates with tombstones.
- Tombstone filtering is done only in `DynDorisClient.client_filter`.
- Add and delete updates create new document versions instead of mutating old
  encrypted postings.
- Add/delete buffer flushing creates fresh run ids and fresh derived run keys.
- Merge decrypts logical records, filters them, and rebuilds fresh Doris runs.
- Merge never concatenates old encrypted cells.
- No stable public `PRF(K, w || id)` delete label is generated.

## Known Limits

- This is a functional prototype, not an optimized implementation.
- The server is in-memory.
- Payload serialization uses Python `pickle`, so it is for local experiments and
  correctness testing only.
- The s-term selection policy is currently `Q[0]`.
- The merge policy is a small leveled policy suitable for toy experiments.
