from Crypto.Random import get_random_bytes
from .cryptoUtils import prf, hash_length
from dataclasses import dataclass
from Crypto.Util.number import long_to_bytes
import random
import math


@dataclass
class HValue:
    # 行数
    b: int
    # 后续的匹配
    L: bytes
    # 密钥
    K: bytes


class TSet:
    # n: 插入元素的数量 k：扩展因子，用于调整集合的大小
    def __init__(self, n: int, k: int):
        # 初始化时会调用 _cal_BS 计算 B和S，B和S都是布隆过滤器的尺寸相关
        self._cal_BS(n, k)
        # self.t_set 是一个二维数组，表示 TSet 的存储结构
        # B 是行数，S 是列数，所有的元素初始为空字节串 b""
        self.t_set = [[b""] * self.S for _ in range(self.B)]

    """
    N = n * k，然后通过 sqrt(N) 得到一个值，最终向上取整得到 logN
    这个值被用于决定 TSet 的行数和列数（B 和 S）
    """

    def _cal_BS(self, n: int, k: int):
        N = n * k
        logN = math.ceil(math.sqrt(N))
        self.B = logN
        self.S = logN

    # (w,id) -> (b,L,K)
    """
    _hash_func作用：根据查询标识（stag）和文档位置索引（i），生成一个哈希值 HValue
    哈希值被分成三个部分：定位 TSet 中的行、后续的匹配和加密操作 
    """

    def _hash_func(self, stag: bytes, i: int) -> HValue:
        # 使用伪随机函数（prf）对 stag 和当前的索引 i 进行哈希处理
        # 3表示hash_length 函数对输入进行 3 次哈希
        tmp = hash_length(prf(stag, long_to_bytes(i)), 3)
        # tmp[:4]：从返回的哈希值 tmp 中取前 4 个字节，转换为一个整数，并对 self.B 取模，得到一个值 b，它用于定位 TSet 中的某一行
        # tmp[4:12] 和 tmp[12:120]：从tmp 中取出不同的部分，分别用作 HValue 中的 L（用于验证，检查L是否匹配） 和 K（用于加密）
        h = HValue(int.from_bytes(tmp[:4], 'big') %
                   self.B, tmp[4:12], tmp[12:120])
        return h

    # TSet[b]: whether the corresponding list is free
    # _free_b 的作用是查找 TSet 中是否有空的单元（即是否有空字节串 b""）
    # 如果找到空位置，它就返回该位置的索引；如果没有空位置，则抛出异常 "insufficient space"。
    def _free_b(self, b: int):
        l_b = self.t_set[b]
        while b"" in l_b:
            j = random.randint(0, self.S - 1)
            if l_b[j] == b"":
                return j
        else:
            raise Exception("insufficient space")

    # _xor: 字节级异或
    def _xor(self, a: bytes, b: bytes) -> bytes:
        return bytes([ai ^ bi for ai, bi in zip(a, b)])

    # setup方法： 插入数据
    def setup(self, T: dict):
        # 生成一个随机密钥
        kt = get_random_bytes(16)
        for w, t in T.items():
            # 使用密钥kt和关键词w生成查询标识stag
            stag = prf(kt, w)
            # 标志位，表示是否为当前列表中的最后一个元素
            beta = 1
            # 遍历每个文档
            for i in range(1, len(t) + 1):
                # 使用stag和索引i计算哈希值h
                h = self._hash_func(stag, i)

                # 在t_set中查找空位置
                j = self._free_b(h.b)
                # 如果是当前文档列表的最后一个元素
                if i == len(t):
                    # 设置beta为0，表示这个位置的标志位为0
                    beta = 0
                # 获取文档对应的信息,并转为bytearray
                s = t[i - 1]
                s = bytearray(s)
                # 将beta插入到文档信息的开头
                s.insert(0, beta)
                # 用K对文档信息做异或操作
                value = self._xor(s, h.K)
                # 存入t_set的对应位置
                # h.b = int.from_bytes(tmp[:4], 'big') % self.B，即TSet的行号
                # j:第 h.b 行里随机找到的一个空位置
                # h.L = tmp[4:12] 作用：查询时定位正确元素
                self.t_set[h.b][j] = h.L + value
        # 返回密钥kt
        return kt

    # retrive方法： 查询数据
    def retrive(self, stag: bytes):
        # 存储查询结果
        t = []
        # 标志位，表示是否继续查询
        beta = 1
        # 从第一个文档开始
        i = 1
        # 只要beta为1，继续查询
        while beta == 1:
            # 计算哈希值h
            h = self._hash_func(stag, i)
            for lv in self.t_set[h.b]:
                # 如果该位置为空，跳过
                if not lv:
                    continue
                # 如果文档的L部分与哈希值匹配
                if lv[:8] == h.L:
                    # 解密文档信息
                    s = self._xor(lv[8:], h.K)
                    # 更新beta标志
                    beta = s[0]
                    # 将解密后的文档添加到结果中
                    t.append(s[1:])
            # 查找下一个文档
            i += 1

            # 如果没有找到任何匹配文档，跳出循环
            if len(t) == 0:
                break
        # 返回查询结果
        return t

# genStag：生成查询标识
def genStag(kt: bytes, w: str) -> bytes:
    return prf(kt, w)


# cal_size：计算 TSet 的内存大小
def cal_size(tset: TSet) -> int:
    size = 0
    for pair_lst in tset.t_set:
        for pair in pair_lst:
            if pair != b"":
                size += len(pair)
    return size
