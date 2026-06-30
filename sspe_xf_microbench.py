import argparse
import cProfile
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter_ns
from typing import Dict, List, Tuple

from Doris_XF import EDB, PARAMS, sspe
from Utils.SSPE_XF import ProfileStats
from Utils.TSet import genStag
from Utils.cryptoUtils import AES_dec, prf
from Utils.fileUtils import read_index


@dataclass
class CandidateCase:
    # CandidateCase 表示“固定一个候选位置 i 后，该候选对应的一整套实验输入”。
    # 在 Doris 查询里，服务器先根据第一个关键词 w1 从 TSet 取回一个候选列表 t。
    # 列表中的第 i 个元素就是第 i 个 candidate。
    # 对这个 candidate，我们会：
    # 1. 解出它对应的文档 id；
    # 2. 取出这个文档里与 w1 共现的其它关键词；
    # 3. 构造 q 个关键词查询；
    # 4. 生成和该 candidate_pos 绑定的 qtag / token；
    # 5. 用它去测 dec() 的耗时。
    candidate_pos: int
    enc_doc: bytes
    doc_id: str
    query_keywords: List[str]
    qtags: List[bytes]
    token: object


def dataset_paths(dataset: str, scale: int) -> Tuple[str, str]:
    return f"./data/{dataset}_inverted{scale}.csv", f"./data/{dataset}_index{scale}.csv"


def unique_keep_order(items: List[str]) -> List[str]:
    # 去重但保留原顺序，避免同一文档关键词列表里重复词影响 q 的构造。
    return list(dict.fromkeys(items))


def choose_anchor_keyword(
    dct_wid: Dict[str, List[str]],
    dct_idw: Dict[str, List[str]],
    max_q: int,
) -> str:
    # 这里自动选一个“锚关键词” anchor_keyword，目的有两个：
    # 1. 让同一次实验中 |XSet| 固定；
    # 2. 让 q 能从 2 一直扫到 max_q，而且每个 q 下都能找到足够多的真实候选。
    #
    # 评分标准：
    # eligible: 以该关键词为 w1 时，能支持 max_q 的候选文档有多少；
    # len(doc_ids): 该关键词本身的倒排列表长度。
    # 我们优先选 eligible 多的，其次选倒排列表更长的。
    best_keyword = None
    best_score = (-1, -1, "")
    need = max_q - 1
    for keyword, doc_ids in dct_wid.items():
        eligible = 0
        for doc_id in doc_ids:
            doc_keywords = unique_keep_order(dct_idw.get(doc_id, []))
            if keyword not in doc_keywords:
                continue
            others = [w for w in doc_keywords if w != keyword]
            if len(others) >= need:
                eligible += 1
        score = (eligible, len(doc_ids), keyword)
        if score > best_score:
            best_keyword = keyword
            best_score = score
    if best_keyword is None or best_score[0] <= 0:
        raise ValueError(f"no keyword can support q up to {max_q}")
    return best_keyword


def build_cases_for_q(
    anchor_keyword: str,
    q: int,
    dct_wid: Dict[str, List[str]],
    dct_idw: Dict[str, List[str]],
    edb: EDB,
    msk,
    keys: PARAMS,
    max_cases: int,
) -> List[CandidateCase]:
    # 这个函数是整份 microbench 最关键的部分：
    # 它不是随便伪造 token，而是严格按 Doris_XF.search() 的语义，
    # 从真实 TSet 恢复出每个 candidate 的位置 i，再构造 qtag。
    #
    # 原因是 Doris 的 qtag = PRF(kx, w1 || wj || i)。
    # 这里的 i 不是任意编号，而是“w1 在 TSet 返回结果列表中的第 i 个候选”。
    # 如果 i 不对，构造出来的 token 就不对应真实协议路径，bench 就失真了。
    stag = genStag(keys.kt, anchor_keyword)
    t = edb.tset.retrive(stag)
    ke = prf(keys.ke, anchor_keyword)
    cases: List[CandidateCase] = []

    for candidate_pos, enc_doc in enumerate(t, start=1):
        doc_id = AES_dec(ke, enc_doc).decode("utf-8")
        # 这里先把候选密文解回文档 id，再通过 id -> 关键词列表索引重建它的真实共现词。
        doc_keywords = unique_keep_order(dct_idw.get(doc_id, []))
        if anchor_keyword not in doc_keywords:
            continue

        others = [w for w in doc_keywords if w != anchor_keyword]
        # 这里不是随机挑共现词，而是优先选更常见的共现关键词。
        # 这样不同轮次跑出来的 q 组合更稳定，也更接近“真实可命中的查询”。
        others = sorted(others, key=lambda kw: (-len(dct_wid.get(kw, [])), kw))
        if len(others) < q - 1:
            continue

        query_keywords = [anchor_keyword] + others[: q - 1]
        qtags = [
            prf(keys.kx, anchor_keyword + other_keyword + str(candidate_pos))
            for other_keyword in query_keywords[1:]
        ]
        # token 预先生成好，后面 pure dec microbench 就只测 dec，不把 keyGen 混进去。
        token = sspe.keyGen(msk, qtags)
        cases.append(
            CandidateCase(
                candidate_pos=candidate_pos,
                enc_doc=enc_doc,
                doc_id=doc_id,
                query_keywords=query_keywords,
                qtags=qtags,
                token=token,
            )
        )
        if len(cases) >= max_cases:
            break

    if not cases:
        raise ValueError(f"no candidate case available for q={q}")
    return cases


def ns_to_us(value: float) -> float:
    return value / 1_000.0


def pct(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return 100.0 * part / total


def run_dec_only_bench(cases: List[CandidateCase], ct, repeat: int) -> Dict[str, float]:
    # 这个函数只回答第 1 个问题：
    # “固定 |XSet| 后，q 从 2 到 10 变化时，每个候选 i 的 dec 平均耗时是多少？”
    #
    # 做法：
    # 1. 先 warmup，减小首次调用抖动；
    # 2. 重复 repeat 轮，只执行 dec()；
    # 3. 总耗时除以 (repeat * candidate_count)，得到 per-candidate 平均耗时；
    # 4. 额外做一轮 dec_profiled()，得到 hash/xor/list index/python overhead 占比。
    for _ in range(3):
        for case in cases:
            sspe.dec(case.token, ct)

    start = perf_counter_ns()
    positive = 0
    for _ in range(repeat):
        for case in cases:
            positive += int(sspe.dec(case.token, ct))
    total_ns = perf_counter_ns() - start

    stats = ProfileStats()
    # 每个 candidate 的 token 和访问路径在这里都是固定的，
    # 因此做一轮 profile 足以估计分项占比，不必把 profile 也重复很多次。
    prof_positive = 0
    for case in cases:
        prof_positive += int(sspe.dec_profiled(case.token, ct, stats))

    per_candidate_ns = total_ns / (repeat * len(cases))
    return {
        "candidate_count": len(cases),
        "positive_count": prof_positive,
        "avg_dec_us_per_candidate": ns_to_us(per_candidate_ns),
        "dec_total_ms": total_ns / 1_000_000.0,
        "dec_hash_pct": pct(stats.hash_ns, stats.total_ns),
        "dec_xor_pct": pct(stats.xor_ns, stats.total_ns),
        "dec_list_index_pct": pct(stats.list_index_ns, stats.total_ns),
        "dec_python_overhead_pct": pct(stats.python_overhead_ns, stats.total_ns),
        "dec_hash_us_per_candidate": ns_to_us(stats.hash_ns / max(len(cases), 1)),
        "dec_xor_us_per_candidate": ns_to_us(stats.xor_ns / max(len(cases), 1)),
        "dec_list_index_us_per_candidate": ns_to_us(stats.list_index_ns / max(len(cases), 1)),
        "dec_python_overhead_us_per_candidate": ns_to_us(
            stats.python_overhead_ns / max(len(cases), 1)
        ),
        "repeat": repeat,
        "bench_positive_count": positive,
    }


def run_candidate_path_profile(
    cases: List[CandidateCase],
    ct,
    msk,
    keys: PARAMS,
    anchor_keyword: str,
) -> Dict[str, float]:
    # 这个函数回答第 2 个问题：
    # 如果看“完整候选处理路径”，时间究竟花在哪？
    #
    # 对单个 candidate，完整路径包含：
    # 1. 重新生成 qtag
    # 2. keyGen（内部又拆成 hash / get_pos / xor）
    # 3. dec（拆成 hash / list index / xor）
    # 4. 若命中，再做 AES 解密恢复文档 id
    #
    # 这样可以和 pure dec 结果对比：
    # - 若 pure dec 已经很重，说明瓶颈就在 dec/XOR filter 访存；
    # - 若完整路径里 hash/get_pos/AES 占大头，说明不能把锅都甩给 XOR filter。
    total_start = perf_counter_ns()
    hash_ns = 0
    aes_ns = 0
    get_pos_ns = 0
    xor_ns = 0
    list_index_ns = 0
    positive = 0
    ke = prf(keys.ke, anchor_keyword)

    for case in cases:
        start = perf_counter_ns()
        qtags = [
            prf(keys.kx, anchor_keyword + other_keyword + str(case.candidate_pos))
            for other_keyword in case.query_keywords[1:]
        ]
        hash_ns += perf_counter_ns() - start

        keygen_stats = ProfileStats()
        token = sspe.keyGen_profiled(msk, qtags, keygen_stats)
        hash_ns += keygen_stats.hash_ns
        get_pos_ns += keygen_stats.get_pos_ns
        xor_ns += keygen_stats.xor_ns

        dec_stats = ProfileStats()
        res = sspe.dec_profiled(token, ct, dec_stats)
        hash_ns += dec_stats.hash_ns
        xor_ns += dec_stats.xor_ns
        list_index_ns += dec_stats.list_index_ns

        if res:
            positive += 1
            start = perf_counter_ns()
            AES_dec(ke, case.enc_doc)
            aes_ns += perf_counter_ns() - start

    total_ns = perf_counter_ns() - total_start
    python_overhead_ns = max(
        total_ns - (hash_ns + get_pos_ns + xor_ns + list_index_ns + aes_ns),
        0,
    )
    return {
        "candidate_total_us_per_candidate": ns_to_us(total_ns / max(len(cases), 1)),
        "candidate_hash_pct": pct(hash_ns, total_ns),
        "candidate_get_pos_pct": pct(get_pos_ns, total_ns),
        "candidate_xor_pct": pct(xor_ns, total_ns),
        "candidate_list_index_pct": pct(list_index_ns, total_ns),
        "candidate_aes_pct": pct(aes_ns, total_ns),
        "candidate_python_overhead_pct": pct(python_overhead_ns, total_ns),
        "candidate_hash_us_per_candidate": ns_to_us(hash_ns / max(len(cases), 1)),
        "candidate_get_pos_us_per_candidate": ns_to_us(get_pos_ns / max(len(cases), 1)),
        "candidate_xor_us_per_candidate": ns_to_us(xor_ns / max(len(cases), 1)),
        "candidate_list_index_us_per_candidate": ns_to_us(list_index_ns / max(len(cases), 1)),
        "candidate_aes_us_per_candidate": ns_to_us(aes_ns / max(len(cases), 1)),
        "candidate_python_overhead_us_per_candidate": ns_to_us(
            python_overhead_ns / max(len(cases), 1)
        ),
        "candidate_positive_count": positive,
    }


def write_csv(path: Path, rows: List[Dict[str, object]]):
    # CSV 采用：
    # 第 1 行：字段名
    # 第 2 行：字段中文解释
    # 第 3 行起：数据
    # 这样直接用 Excel 打开时，不需要回头翻代码找每列是什么意思。
    if not rows:
        return
    summary_comments = {
        "dataset": "数据集名称 例如 enron 或 enwiki",
        "scale": "数据集规模编号 对应 data 下的 scale 版本",
        "anchor_keyword": "本次实验固定的第一个查询关键词 w1",
        "xset_slots": "固定 XSet 编码后 XOR Filter 的槽位数 可视为固定 |XSet| 的规模代理",
        "q": "查询关键词总数，从 2 扫到 10",
        "candidate_count": "该 q 下实际参与 dec microbench 的候选 i 数量",
        "positive_count": "profiled dec 中返回 True 的候选数",
        "avg_dec_us_per_candidate": "核心指标 平均每个候选 i 执行一次 dec 的耗时 单位微秒",
        "dec_total_ms": "该 q 下 pure dec 总耗时，单位毫秒",
        "dec_hash_pct": "只看 dec 时，PRF 校验耗时占比",
        "dec_xor_pct": "只看 dec 时，异或操作耗时占比",
        "dec_list_index_pct": "只看 dec 时 ct.array[idx] 列表取值耗时占比",
        "dec_python_overhead_pct": "只看 dec 时，其余 Python 解释器开销占比",
        "dec_hash_us_per_candidate": "只看 dec 时 每个候选分摊到的哈希耗时 微秒",
        "dec_xor_us_per_candidate": "只看 dec 时 每个候选分摊到的 XOR 耗时 微秒",
        "dec_list_index_us_per_candidate": "只看 dec 时 每个候选分摊到的列表取值耗时 微秒",
        "dec_python_overhead_us_per_candidate": "只看 dec 时 每个候选分摊到的其余 Python 开销 微秒",
        "repeat": "pure dec 基准重复轮数",
        "bench_positive_count": "pure dec 基准所有重复轮次中返回 True 的总次数",
        "candidate_total_us_per_candidate": "完整 candidate 路径下 每个候选总耗时 微秒",
        "candidate_hash_pct": "完整路径中，哈希/PRF 相关耗时占比",
        "candidate_get_pos_pct": "完整路径中，get_pos 计算位置集合耗时占比",
        "candidate_xor_pct": "完整路径中，异或操作耗时占比",
        "candidate_list_index_pct": "完整路径中，列表取值耗时占比",
        "candidate_aes_pct": "完整路径中，AES 解密耗时占比",
        "candidate_python_overhead_pct": "完整路径中，其余 Python 解释器开销占比",
        "candidate_hash_us_per_candidate": "完整路径中 每个候选分摊到的哈希耗时 微秒",
        "candidate_get_pos_us_per_candidate": "完整路径中 每个候选分摊到的 get_pos 耗时 微秒",
        "candidate_xor_us_per_candidate": "完整路径中 每个候选分摊到的 XOR 耗时 微秒",
        "candidate_list_index_us_per_candidate": "完整路径中 每个候选分摊到的列表取值耗时 微秒",
        "candidate_aes_us_per_candidate": "完整路径中 每个候选分摊到的 AES 耗时 微秒",
        "candidate_python_overhead_us_per_candidate": "完整路径中 每个候选分摊到的其余 Python 开销 微秒",
        "candidate_positive_count": "完整路径中命中的候选数量",
    }
    case_comments = {
        "q": "查询关键词总数",
        "candidate_pos": "该候选在 TSet 返回列表中的位置 i，从 1 开始",
        "doc_id": "该候选对应的真实文档 id",
        "query_keywords": "用于该候选实验的真实查询关键词组合，使用 | 分隔",
    }
    comment_map = summary_comments if "summary_" in path.name else case_comments
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerow({key: comment_map.get(key, "") for key in rows[0].keys()})
        writer.writerows(rows)


def dump_case_preview(path: Path, cases_by_q: Dict[int, List[CandidateCase]]):
    # 这个文件不是拿来画性能图的，而是拿来审计实验输入是否合理。
    # 每个 q 只保存前几个样例，方便人工检查：
    # “到底选了哪个 candidate、对应哪篇文档、拼出来的查询词是什么”。
    rows = []
    for q, cases in cases_by_q.items():
        for case in cases[:5]:
            rows.append(
                {
                    "q": q,
                    "candidate_pos": case.candidate_pos,
                    "doc_id": case.doc_id,
                    "query_keywords": "|".join(case.query_keywords),
                }
            )
    write_csv(path, rows)


def build_profile_workload(
    profile_kind: str,
    loops: int,
    cases: List[CandidateCase],
    ct,
    msk,
    keys: PARAMS,
    anchor_keyword: str,
):
    # cProfile / py-spy 需要一个足够“热”的循环，不然采样点太少。
    # 这里把真实协议路径包装成可重复执行的 workload，避免分析器看到的代码路径和 bench 不一致。
    def workload():
        if profile_kind == "dec":
            for _ in range(loops):
                for case in cases:
                    sspe.dec(case.token, ct)
        else:
            ke = prf(keys.ke, anchor_keyword)
            for _ in range(loops):
                for case in cases:
                    qtags = [
                        prf(keys.kx, anchor_keyword + other_keyword + str(case.candidate_pos))
                        for other_keyword in case.query_keywords[1:]
                    ]
                    token = sspe.keyGen(msk, qtags)
                    if sspe.dec(token, ct):
                        AES_dec(ke, case.enc_doc)

    return workload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="enron", choices=["enron", "enwiki"])
    parser.add_argument("--scale", type=int, default=1)
    parser.add_argument("--min-q", type=int, default=2)
    parser.add_argument("--max-q", type=int, default=10)
    parser.add_argument("--max-cases", type=int, default=64)
    parser.add_argument("--repeat", type=int, default=200)
    parser.add_argument("--tset-k", type=int, default=2)
    parser.add_argument("--out-dir", default="./log/sspe_xf_microbench")
    parser.add_argument("--cprofile-q", type=int)
    parser.add_argument("--profile-kind", default="dec", choices=["dec", "candidate"])
    parser.add_argument("--profile-loops", type=int, default=300)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fpath_wid, fpath_idw = dataset_paths(args.dataset, args.scale)
    dct_wid = read_index(fpath_wid)
    dct_idw = read_index(fpath_idw)

    keys = PARAMS()
    # 直接复用 Doris_XF 的真实 setup，确保：
    # 1. XSet 规模来自真实数据集；
    # 2. 真实使用仓库里的 Enron/Enwiki 子集，而不是人工伪造集合。
    edb = EDB(sum(len(v) for v in dct_wid.values()), args.tset_k)
    msk = edb.setup(fpath_wid, fpath_idw, keys)
    xset_size = len(edb.ct.array)

    anchor_keyword = choose_anchor_keyword(dct_wid, dct_idw, args.max_q)

    cases_by_q: Dict[int, List[CandidateCase]] = {}
    summary_rows: List[Dict[str, object]] = []
    json_rows: List[Dict[str, object]] = []

    for q in range(args.min_q, args.max_q + 1):
        # 对每个 q，固定 |XSet| 不变，只改变查询关键词数。
        cases = build_cases_for_q(
            anchor_keyword,
            q,
            dct_wid,
            dct_idw,
            edb,
            msk,
            keys,
            args.max_cases,
        )
        cases_by_q[q] = cases

        dec_summary = run_dec_only_bench(cases, edb.ct, args.repeat)
        candidate_summary = run_candidate_path_profile(cases, edb.ct, msk, keys, anchor_keyword)
        row = {
            "dataset": args.dataset,
            "scale": args.scale,
            "anchor_keyword": anchor_keyword,
            "xset_slots": xset_size,
            "q": q,
            **dec_summary,
            **candidate_summary,
        }
        summary_rows.append(row)
        json_rows.append(row)

    stem = f"{args.dataset}{args.scale}_{anchor_keyword}"
    summary_path = out_dir / f"summary_{stem}.csv"
    json_path = out_dir / f"summary_{stem}.json"
    preview_path = out_dir / f"cases_{stem}.csv"

    write_csv(summary_path, summary_rows)
    dump_case_preview(preview_path, cases_by_q)
    json_path.write_text(json.dumps(json_rows, indent=2), encoding="utf-8")

    print(f"dataset={args.dataset}{args.scale}")
    print(f"anchor_keyword={anchor_keyword}")
    print(f"xset_slots={xset_size}")
    print(f"summary_csv={summary_path}")
    print(f"summary_json={json_path}")
    print(f"case_preview_csv={preview_path}")

    if args.cprofile_q is not None:
        profile_cases = cases_by_q[args.cprofile_q]
        profile_path = out_dir / f"cprofile_{stem}_q{args.cprofile_q}_{args.profile_kind}.prof"
        profiler = cProfile.Profile()
        profiler.runcall(
            build_profile_workload(
                args.profile_kind,
                args.profile_loops,
                profile_cases,
                edb.ct,
                msk,
                keys,
                anchor_keyword,
            )
        )
        profiler.dump_stats(str(profile_path))
        print(f"cprofile_file={profile_path}")


if __name__ == "__main__":
    main()
