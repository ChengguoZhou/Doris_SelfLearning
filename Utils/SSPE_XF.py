from dataclasses import dataclass
from time import perf_counter_ns
from typing import List
import math
import sys

from Crypto.Random import get_random_bytes

from .cryptoUtils import prf
from .XorFilter import XorFilter, get_pos

byteorder = sys.byteorder


@dataclass
class s:
    sk1: bytes
    sk2: bytes
    S: List[int]


@dataclass
class MSK:
    sk: bytes
    k: int
    m: int
    seed: int = 0


@dataclass
class MSK_XF:
    msk: MSK
    xf: XorFilter


@dataclass
class ProfileStats:
    # 下面这些字段不是协议里的逻辑量，而是 microbench/profiling 时附加记录的时间统计。
    # 单位统一为纳秒（ns），便于后续再换算成 us/ms。
    # total_ns: 当前阶段总耗时。
    # hash_ns: PRF/HMAC 这类哈希相关计算耗时。
    # get_pos_ns: get_pos() 里根据若干 qtag 计算 XOR Filter 下标集合 S 的耗时。
    # xor_ns: 真正做 32 字节异或的耗时。
    # list_index_ns: 访问 ct.array[idx] 这种 Python 列表取值的耗时。
    # aes_ns: 候选通过过滤后，执行 AES 解密恢复文档 id 的耗时。
    # python_overhead_ns: 除上面已显式拆分的部分外，其余解释器开销。
    total_ns: int = 0
    hash_ns: int = 0
    get_pos_ns: int = 0
    xor_ns: int = 0
    list_index_ns: int = 0
    aes_ns: int = 0
    python_overhead_ns: int = 0
    call_count: int = 0
    candidate_count: int = 0

    def add_call(self, total_ns: int, **parts: int):
        # 先把显式拆分出来的子项累计，再把剩余部分记到 python_overhead_ns。
        # 这样最终 total = 已知分类 + python_overhead，可以直接做占比图。
        part_total = 0
        for name, value in parts.items():
            setattr(self, name, getattr(self, name) + value)
            part_total += value
        self.total_ns += total_ns
        self.python_overhead_ns += max(total_ns - part_total, 0)
        self.call_count += 1


class SSPE_XF:
    def __init__(self):
        lam = 256
        # zero_vec 是 Doris/SSPE_XF 里最终一致性校验的固定输入。
        # dec() 恢复出候选 key K 后，会再计算一次 prf(K, zero_vec)
        # 与 token 里的 sk2 对比，从而判断“这些查询标签是否都被集合覆盖”。
        self.zero_vec = b"0" * ((lam + math.ceil(math.log2(lam))) // 8)

    def _xor(self, a: bytes, b: bytes) -> bytes:
        # 这里保持与原实现一致：把 32 字节串转成整数做异或，再转回 32 字节。
        # 这个写法在 Python 里比逐字节列表推导更接近原作者的实现路径，
        # 也更适合我们后面单独测 “XOR 本身” 的耗时。
        int_a = int.from_bytes(a, byteorder)
        int_b = int.from_bytes(b, byteorder)
        return (int_a ^ int_b).to_bytes(32, byteorder)

    def setup(self, n: int) -> MSK_XF:
        # setup 只负责生成主密钥和空的 XOR Filter，不做数据写入。
        sk = get_random_bytes(32)
        xf = XorFilter(n)
        return MSK_XF(MSK(sk, 3, xf.s), xf)

    def keyGen(self, msk: MSK, X: List[str]) -> s:
        # X 是查询方构造好的 qtag 集合。
        # 其输出 token = (sk1, sk2, S)：
        # 1. sk2 是最终校验值；
        # 2. sk1 把随机 K 和所有 PRF 标签异或在一起；
        # 3. S 是查询时要访问的 XOR Filter 下标集合。
        K = get_random_bytes(32)
        sk2 = prf(K, self.zero_vec)
        sk1 = K
        tmps = [prf(msk.sk, x) for x in X]
        S = get_pos(tmps, msk.k, msk.m, msk.seed)
        for tmp in tmps:
            sk1 = self._xor(sk1, tmp)
        return s(sk1, sk2, S)

    def keyGen_profiled(self, msk: MSK, X: List[str], stats: ProfileStats) -> s:
        # 这个接口与 keyGen() 逻辑等价，只是把时间拆成 3 类：
        # 1. PRF 计算
        # 2. get_pos() 计算位置集合 S
        # 3. 把若干标签累计异或进 sk1
        # 这样在“完整 candidate 路径”里，就能区分时间到底花在标签生成还是 filter 访存上。
        total_start = perf_counter_ns()
        hash_ns = 0
        get_pos_ns = 0
        xor_ns = 0

        K = get_random_bytes(32)

        start = perf_counter_ns()
        sk2 = prf(K, self.zero_vec)
        hash_ns += perf_counter_ns() - start

        sk1 = K
        tmps = []
        for x in X:
            start = perf_counter_ns()
            tmps.append(prf(msk.sk, x))
            hash_ns += perf_counter_ns() - start

        start = perf_counter_ns()
        S = get_pos(tmps, msk.k, msk.m, msk.seed)
        get_pos_ns += perf_counter_ns() - start

        for tmp in tmps:
            start = perf_counter_ns()
            sk1 = self._xor(sk1, tmp)
            xor_ns += perf_counter_ns() - start

        stats.add_call(
            perf_counter_ns() - total_start,
            hash_ns=hash_ns,
            get_pos_ns=get_pos_ns,
            xor_ns=xor_ns,
        )
        return s(sk1, sk2, S)

    def enc(self, msk_bf: MSK_XF, Y: List[str]):
        # Y 是要被编码进 XOR Filter 的全集元素。
        # 在 Doris_XF 里，这里对应的是所有 xtag 组成的 XSet。
        msk = msk_bf.msk
        xf = msk_bf.xf
        xf.update([prf(msk.sk, y) for y in Y])
        # XorFilter.update() 在建表失败时可能会自动更换 seed 重试。
        # 因此必须把最终 seed 回写到 msk，确保后续 keyGen/dec 看到的是同一组哈希函数。
        msk.seed = xf.get_seed()

    def dec(self, token: s, ct: XorFilter) -> bool:
        # dec 的语义非常直接：
        # 1. 从 token.sk1 开始；
        # 2. 依次取出 token.S 中对应的 filter 槽位做异或；
        # 3. 若查询条件成立，则这些量会抵消回原始 K；
        # 4. 最后通过 prf(K, zero_vec) == sk2 判定真假。
        xor_res = token.sk1
        for idx in token.S:
            xor_res = self._xor(ct.array[idx], xor_res)
        return token.sk2 == prf(xor_res, self.zero_vec)

    def dec_profiled(self, token: s, ct: XorFilter, stats: ProfileStats) -> bool:
        # 这个接口专门给 microbench 用，和 dec() 逻辑保持一致。
        # 这里特地把“列表取值”和“异或计算”拆开统计，
        # 是为了回答你关心的问题：瓶颈到底来自 XOR filter 本体，
        # 还是 Python 对象/列表访问这种实现层开销。
        total_start = perf_counter_ns()
        xor_ns = 0
        hash_ns = 0
        list_index_ns = 0

        xor_res = token.sk1
        for idx in token.S:
            start = perf_counter_ns()
            value = ct.array[idx]
            list_index_ns += perf_counter_ns() - start

            start = perf_counter_ns()
            xor_res = self._xor(value, xor_res)
            xor_ns += perf_counter_ns() - start

        start = perf_counter_ns()
        res = token.sk2 == prf(xor_res, self.zero_vec)
        hash_ns += perf_counter_ns() - start

        stats.add_call(
            perf_counter_ns() - total_start,
            hash_ns=hash_ns,
            xor_ns=xor_ns,
            list_index_ns=list_index_ns,
        )
        stats.candidate_count += 1
        return res
