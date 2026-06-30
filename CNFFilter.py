"""
CNFFilter from Patel et al. (2021).

The setup phase follows the pair-indexed construction used by the paper:
an sEMM/TSet stores encrypted tags and encrypted values for every keyword pair,
while X stores the corresponding double tags for membership filtering.
和论文中出入的地方：
1.单子句 CNF 的处理（CNFFilter.py:137）：
    论文说这是特例，可退到 BIEX 风格；你这里直接查询 (w,w) 并做并集。
2.论文伪代码写法是“先 union，再统一解密去重”（CNFFilter.py:191）；
    你这里用 dict[tag] = ev 直接去重。
"""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Tuple
from Crypto.Random import get_random_bytes
import struct

from Utils.TSet import TSet, genStag
from Utils.cryptoUtils import AES_dec, AES_enc, prf
from Utils.fileUtils import read_index

# 生成两个单词组成的唯一键，避免重复
def _pair_key(word_a: str, word_b: str) -> str:
    # Add an explicit separator to avoid collisions such as "ab|c" == "a|bc".
    return f"{word_a}|{word_b}"

# 处理和规范化CNF（合取范式）子句，去重
def _normalize_clauses(clauses: Sequence[Sequence[str]]) -> List[List[str]]:
    normalized = []
    for clause in clauses:
        dedup_clause = []
        seen = set()
        for word in clause:
            if word not in seen:
                seen.add(word)
                dedup_clause.append(word)
        if not dedup_clause:
            raise ValueError("CNF clauses must be non-empty.")
        normalized.append(dedup_clause)
    if not normalized:
        raise ValueError("At least one CNF clause is required.")
    return normalized

# 定义用于加密的多个密钥
@dataclass
class PARAMS:
    # 用 default_factory 保证每次实例化都重新采样随机密钥，
    # 而不是在类定义时只生成一次并被所有 PARAMS 实例共享。
    kt: bytes = field(default_factory=lambda: get_random_bytes(16))
    kp: bytes = field(default_factory=lambda: get_random_bytes(16))
    kx: bytes = field(default_factory=lambda: get_random_bytes(16))
    kenc: bytes = field(default_factory=lambda: get_random_bytes(16))
    msk: bytes = None

# 存储加密索引(EMM)和双标签集合(X)
class EDB:
    def __init__(self, k: int) -> None:
        self.k = k
        self.EMM = None
        self.X = set()

    @staticmethod
    def _set_intersection(values_a: Iterable[str], values_b: Iterable[str]):
        return set(values_a) & set(values_b)

    # setup方法读取索引文件，构建加密标签和文档索引，并填充双标签集合X
    def setup(self, fpath_wid: str, keys: PARAMS):
        # mm 对应论文里的 MMp:
        # key 是有序关键词对 (a, b)，value 是所有 v in MM[a]∩MM[b]
        # 对应的加密标签/加密文档标识列表。
        mm = {}
        dct_wid = read_index(fpath_wid)

        count = 0
        # 通过 PRF（伪随机函数） 生成与每对关键词相关的密钥
        for word_a, lst_a in dct_wid.items():
            kt_a = prf(keys.kt, word_a)
            for word_b, lst_b in dct_wid.items():
                vs = self._set_intersection(lst_a, lst_b)
                if not vs:
                    continue

                pair = _pair_key(word_a, word_b)
                kenc_ab = prf(keys.kp, pair)
                kx_ab = prf(keys.kx, pair)
                t = []

                # 生成加密标签(etag)和加密值(ev)，和双标签集合(X)
                for value in vs:
                    # 论文 Figure 1 / Figure 2 的关键点：
                    # tag_a,v 只依赖第一个关键词 a，而不是 (a, b)。
                    # 这样后续对固定 a 的不同 pair 结果做 union/filter 时，
                    # 同一 value 会映射到同一个 tag，服务器才能按 tag 去重和过滤。
                    tag_av = prf(kt_a, value)
                    etag_av = AES_enc(kenc_ab, tag_av)
                    ev_v = AES_enc(keys.kenc, value)
                    t.append(struct.pack("H", len(etag_av)) + etag_av + ev_v)
                    # X 对应论文里的 double-tag 集合：
                    # 存的是 F(Kx_{a,b}, tag_{a,v})，供搜索阶段做 membership filter。
                    self.X.add(prf(kx_ab, tag_av))

                mm[pair] = t
                count += len(t)

        self.EMM = TSet(max(count, 1), self.k)
        keys.msk = self.EMM.setup(mm)


@dataclass
class PairToken:
    stag: bytes
    kenc: bytes


@dataclass
class TOKEN:
    clauses: List[List[str]]
    first_two_tokens: Dict[Tuple[int, int], PairToken]
    first_clause_filter_keys: Dict[Tuple[int, int], bytes]
    later_clause_filter_keys: Dict[Tuple[int, int, int], bytes]


def _retrieve_pair_items(pair_token: PairToken, edb: EDB) -> List[Tuple[bytes, bytes]]:
    # 对应论文 Search 阶段里：
    # 先 sEMM.Search 取回 (etag, ev)，再用 Kenc_{a,b} 解开 etag 得到 tag。
    raw_items = edb.EMM.retrive(pair_token.stag)
    parsed_items = []
    for item in raw_items:
        (length,) = struct.unpack("H", item[:2])
        etag = item[2 : 2 + length]
        ev = item[2 + length :]
        tag = AES_dec(pair_token.kenc, etag)
        parsed_items.append((tag, ev))
    return parsed_items

# c_gen_token()：根据给定的 CNF 子句生成加密查询的 token。
# 它涉及对 CNF 中每一对单词生成加密标签（stag）和用于解密的密钥
def c_gen_token(clauses: Sequence[Sequence[str]], keys: PARAMS) -> TOKEN:
    normalized = _normalize_clauses(clauses)

    first_two_tokens: Dict[Tuple[int, int], PairToken] = {}
    first_clause_filter_keys: Dict[Tuple[int, int], bytes] = {}
    later_clause_filter_keys: Dict[Tuple[int, int, int], bytes] = {}

    if len(normalized) == 1:
        # 论文把“单子句 CNF = 析取”作为特例省略，正文说可退化到 BIEX 风格处理。
        # 这里实现成：查询所有 (w, w) 项并做并集。
        # 因为 setup 已经存了 MM[w]∩MM[w] = MM[w]，所以结果是等价的。
        for i, word in enumerate(normalized[0]):
            pair = _pair_key(word, word)
            first_two_tokens[(i, 0)] = PairToken(
                stag=genStag(keys.msk, pair),
                kenc=prf(keys.kp, pair),
            )
        return TOKEN(normalized, first_two_tokens, first_clause_filter_keys, later_clause_filter_keys)

    for i, word_a in enumerate(normalized[0]):
        for j, word_b in enumerate(normalized[1]):
            # Figure 2, Token Step 2:
            # 为 D1 和 D2 的每个标签对 (`1,i, `2,j) 生成 sEMM token 和解密标签用的 key。
            pair = _pair_key(word_a, word_b)
            first_two_tokens[(i, j)] = PairToken(
                stag=genStag(keys.msk, pair),
                kenc=prf(keys.kp, pair),
            )

    for i, word_a in enumerate(normalized[0]):
        for r in range(i + 1, len(normalized[0])):
            word_r = normalized[0][r]
            # Figure 2, Token Step 3:
            # 这些 key 用来把 D1∧D2 的并集切分成互不重叠的 S_i 分区。
            first_clause_filter_keys[(i, r)] = prf(keys.kx, _pair_key(word_a, word_r))

    # clause_idx: 子句索引 i: 第一个子句的第i个标签 label_idx: 第clause_idx个子句的第label_idx个标签
    for clause_idx in range(2, len(normalized)):
        for i, word_a in enumerate(normalized[0]):
            for label_idx, word_b in enumerate(normalized[clause_idx]):
                # Figure 2, Token Step 4:
                # 之后每个更晚的子句 D3, D4, ... 都会对每个 S_i 做一次“至少命中一个标签”的过滤。
                later_clause_filter_keys[(clause_idx, i, label_idx)] = prf(
                    keys.kx, _pair_key(word_a, word_b)
                )

    return TOKEN(normalized, first_two_tokens, first_clause_filter_keys, later_clause_filter_keys)

# s_search():在 EDB 中进行查询，返回加密结果
def s_search(token: TOKEN, edb: EDB) -> List[bytes]:
    clauses = token.clauses

    if len(clauses) == 1:
        # 单子句时直接做并集，等价于析取查询 D1。
        union_items: Dict[bytes, bytes] = {}
        for i, _ in enumerate(clauses[0]):
            for tag, ev in _retrieve_pair_items(token.first_two_tokens[(i, 0)], edb):
                union_items[tag] = ev
        return list(union_items.values())

    # Each S_i is keyed by tag so that unions across the second clause deduplicate naturally.
    partition_sets: List[Dict[bytes, bytes]] = []
    for i, _ in enumerate(clauses[0]):
        current_items: Dict[bytes, bytes] = {}
        for j, _ in enumerate(clauses[1]):
            # Figure 2, Search Step 2(a)(b):
            # S_i 先收集 MM[`1,i ∧ `2,1], ..., MM[`1,i ∧ `2,q2] 的并集。
            for tag, ev in _retrieve_pair_items(token.first_two_tokens[(i, j)], edb):
                current_items[tag] = ev

        # Partition the union by removing items that will be assigned to a later label in D1.
        filtered_items: Dict[bytes, bytes] = {}
        for tag, ev in current_items.items():
            should_remove = False
            for r in range(i + 1, len(clauses[0])):
                # Figure 2, Search Step 2(e):
                # 如果 tag 同时也属于后面的某个 `1,r，那么它应该被分配给更后的分区 S_r，
                # 当前 S_i 需要删掉它，才能保证 S_1,...,S_q1 两两不交。
                dtag = prf(token.first_clause_filter_keys[(i, r)], tag)
                if dtag in edb.X:
                    should_remove = True
                    break
            if not should_remove:
                filtered_items[tag] = ev
        partition_sets.append(filtered_items)

    # Filter with D3, D4, ...; an item survives if it matches at least one label in each clause.
    for clause_idx in range(2, len(clauses)):
        for i, current_items in enumerate(partition_sets):
            next_items: Dict[bytes, bytes] = {}
            for tag, ev in current_items.items():
                keep_item = False
                for label_idx, _ in enumerate(clauses[clause_idx]):
                    # 论文正文 4.1 的意思是：
                    # 只要 tag 在当前子句 D_d 的某个标签上命中一次，就保留；
                    # 如果一个标签都命不中，才删除。
                    dtag = prf(token.later_clause_filter_keys[(clause_idx, i, label_idx)], tag)
                    if dtag in edb.X:
                        keep_item = True
                        break
                if keep_item:
                    next_items[tag] = ev
            partition_sets[i] = next_items

    enc_res = []
    for current_items in partition_sets:
        enc_res.extend(current_items.values())
    return enc_res

# c_resolve(): 解密并去重加密结果，返回去重后的明文值
def c_resolve(enc_res: List[bytes], keys: PARAMS) -> List[bytes]:
    # Resolve 对应论文最后一步：只解密真正返回给客户端的 value 密文。
    res = []
    seen = set()
    for ev in enc_res:
        value = AES_dec(keys.kenc, ev)
        if value in seen:
            continue
        seen.add(value)
        res.append(value)
    return res


def search(clauses: Sequence[Sequence[str]], edb: EDB, keys: PARAMS) -> List[bytes]:
    token = c_gen_token(clauses, keys)
    enc_res = s_search(token, edb)
    return c_resolve(enc_res, keys)


def eval_plaintext_cnf(clauses: Sequence[Sequence[str]], wid: Dict[str, List[str]]) -> List[str]:
    normalized = _normalize_clauses(clauses)
    clause_sets = []
    for clause in normalized:
        union_set = set()
        for word in clause:
            union_set.update(wid.get(word, []))
        clause_sets.append(union_set)
    result = set.intersection(*clause_sets) if clause_sets else set()
    return sorted(result)


if __name__ == "__main__":
    from time import time

    filename = "./data/enron_inverted0.csv"
    # clauses = [["trade", "buyer"], ["juan", "gas"], ["natural"]]
    clauses = [["trade", "buyer"]]
    k = 2

    start = time()
    keys = PARAMS()
    edb = EDB(k)
    edb.setup(filename, keys)
    end = time()
    print(f"edb setup: {end-start} s")

    start = time()
    token = c_gen_token(clauses, keys)
    end = time()
    print(f"gen token: {end-start} s")

    start = time()
    enc_res = s_search(token, edb)
    end = time()
    print(f"search: {end-start} s")

    start = time()
    res = c_resolve(enc_res, keys)
    end = time()
    print(f"resolve: {end-start} s")
    print(f"encrypted result count: {len(enc_res)}")
    print(f"result: {res}")

    wid = read_index(filename)
    expected = eval_plaintext_cnf(clauses, wid)
    decoded = sorted(value.decode("utf-8") for value in res)
    print(f"plaintext expected: {expected}")
    print(f"match: {decoded == expected}")
