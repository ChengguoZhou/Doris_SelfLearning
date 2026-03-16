"""
ConjFilter original scheme
"""

from Crypto.Random import get_random_bytes
from typing import List
import struct
from Utils.cryptoUtils import prf, AES_enc, AES_dec
from Utils.TSet import TSet, genStag
from Utils.fileUtils import read_index
from dataclasses import dataclass

# PARAMS: 所有密钥
@dataclass
class PARAMS:
    # 用来生成 tag 种子
    kt: bytes = get_random_bytes(16)
    # 用来生成 TSet里 tag 的加密密钥
    kp: bytes = get_random_bytes(16)
    # 用来生成 double tag 的 key
    kx: bytes = get_random_bytes(16)
    # 全局 value 加密密钥 （负责把真实文档 ID / value 加密起来）
    kenc: bytes = get_random_bytes(16)
    # TSet 查询主密钥， 后面生成stag用
    msk: bytes = None


class EDB:
    def __init__(self, k: int) -> None:
        self.k = k
        # EMM 底层是TSet，存放的是所有(word_a, word_b)交集结果
        # 以(etag_a,v | ev_v)形式存储
        self.EMM = None  # tset
        # X 底层是Python中的set，是所有double tag的集合
        self.X = set()  # xset

    def _set_intersection(self, lst1, lst2):
        return set(lst1) & set(lst2)

    # 建库
    def setup(self, fpath_wid: str, keys: PARAMS):
        MM = dict()

        # 读入倒排索引
        dct_wid = read_index(fpath_wid)

        count = 0  # Counts the number of elements to be inserted into the TSet
        # 先枚举所有关键词对（有序二元组，即(a,b)≠(b,a)）
        for word_a, lst_a in dct_wid.items():
            for word_b, lst_b in dct_wid.items():
                if word_a == word_b:
                    continue

                # 求二元交集
                vs = self._set_intersection(lst_a, lst_b)
                # 如果 vs 是空的，就跳过这一次循环
                if not vs:
                    continue

                # TSet
                # 以第一个关键词 a 派生 tag key
                kt_a = prf(keys.kt, word_a)
                # (a,b) 对应的 tag 解密密钥
                kenc_ab = prf(keys.kp, word_a + word_b)

                # XSet
                # (a,b) 对应的 double-tag key
                kx_ab = prf(keys.kx, word_a + word_b)

                t = []

                for v in vs:
                    # TSet
                    # tag只依赖 (关键词a, 文档标识符v)， 后续过滤成功关键
                    tag_av = prf(kt_a, v)
                    # TSet中存的是加密tag + 加密value
                    etag_av = AES_enc(kenc_ab, tag_av)
                    ev_v = AES_enc(keys.kenc, v)
                    # struct.pack 无符号短整型
                    element = struct.pack("H", len(etag_av)) + etag_av + ev_v
                    t.append(element)
                    # TODO: Correctness testing
                    # print(word_a,word_b,v)

                    # XSet
                    # XSet中存 double tag，供后续 membership test 过滤使用
                    self.X.add(prf(kx_ab, tag_av))
                # 在实际工程上最好加分隔符，否则会出现"ab"+"c"和"a"+"bc"相同的情况
                MM[word_a + word_b] = t
                # count是TSet存储集合的数量
                count += len(t)
        # TODO: Correctness testing
        # print(f"xset element number: {len(self.X)}")

        # 最后建立TSet
        self.EMM = TSet(count, self.k)
        # 返回查询所需的主密钥msk
        keys.msk = self.EMM.setup(MM)


"""
Complete search process
"""

# ws 待查询关键词列表，例如ws = ["trade", "buyer"]表示查询trade ∩ buyer
def search(ws: List[str], edb: EDB, keys: PARAMS) -> List[int]:
    # token
    # 给TSet用的搜索标签，用来取(w1, w2)的桶
    stag = genStag(keys.msk, ws[0] + ws[1])
    # kenc_12 用于解密(w1, w2)对应记录里的etag
    kenc_12 = prf(keys.kp, ws[0] + ws[1])
    # 后续过滤 key
    kxs = []
    for i in range(2, len(ws)):
        kx_i = prf(keys.kx, ws[0] + ws[i])
        kxs.append(kx_i)

    # tset&xset
    # 从TSet中取出（w1, w2）的候选
    t = edb.EMM.retrive(stag)

    tag_lst = []
    ev_lst = []
    for i, item in enumerate(t):
        # 分离出etag ev
        (l,) = struct.unpack("H", item[:2])
        etag_l = item[2 : 2 + l]
        ev_l = item[2 + l :]

        # 解密etag，得到tag
        tag_l = AES_dec(kenc_12, etag_l)
        tag_lst.append(tag_l)
        ev_lst.append(ev_l)
    # 搜索结果
    end = []
    # 方案最核心的地方：对于(w1 ∩ w2)的每一个候选Value
    for i in range(len(t)):
        for d in range(2, len(ws)):
            # 用(w1, w3)(w1, w4)...的key算dtag
            dtag_ld = prf(kxs[d - 2], tag_lst[i])
            # 如果有一个不在X中，就跳出循环
            if dtag_ld not in edb.X:
                break
        else:
            # 遍历完后发现待搜索关键词全都在，
            # 说明这个value属于所有关键词，则将ev解密后放入end中
            # 在真实的CS系统中，keys.enc应该只在客户端
            ind = AES_dec(keys.kenc, ev_lst[i])
            end.append(ind)
    return end


"""
every step
"""


@dataclass
class TOKEN:
    stag: bytes
    kenc_12: bytes
    kxs: List[bytes]

# 后面的c_gen_token、s_search、c_resolve像是论文算法拆分
def c_gen_token(ws: List[str], keys: PARAMS) -> TOKEN:
    stag = genStag(keys.msk, ws[0] + ws[1])
    kenc_12 = prf(keys.kp, ws[0] + ws[1])
    kxs = []
    for i in range(2, len(ws)):
        kx_i = prf(keys.kx, ws[0] + ws[i])
        kxs.append(kx_i)
    return TOKEN(stag, kenc_12, kxs)


def s_search(token: TOKEN, edb: EDB, ws_len: int) -> List[bytes]:
    t = edb.EMM.retrive(token.stag)

    tag_lst = []
    ev_lst = []
    for i, item in enumerate(t):
        (l,) = struct.unpack("H", item[:2])
        etag_l = item[2 : 2 + l]
        ev_l = item[2 + l :]

        tag_l = AES_dec(token.kenc_12, etag_l)
        tag_lst.append(tag_l)
        ev_lst.append(ev_l)

    enc_res = []

    for i in range(len(t)):
        for d in range(2, ws_len):
            dtag_ld = prf(token.kxs[d - 2], tag_lst[i])
            if dtag_ld not in edb.X:
                break
        else:
            enc_res.append(ev_lst[i])
    return enc_res


def c_resolve(enc_res: List[bytes], keys: PARAMS):
    res = [AES_dec(keys.kenc, e) for e in enc_res]
    return res


if __name__ == "__main__":
    from time import time

    """
    test case
    """
    # small database
    filename = "./data/enron_inverted0.csv"
    ws = ["trade", "buyer"]  # 13,14
    ws = ["trade", "buyer", "juan", "gas"]
    n = 100
    k = 2

    """
    edb setup 
    """
    start = time()
    keys = PARAMS()
    edb = EDB(k)
    edb.setup(filename, keys)
    end = time()
    print(f"edb setup: {end-start} s")

    """
    Complete search process
    """
    inds = search(ws, edb, keys)
    print(inds)

    """
    Each step of the search process
    """
    start = time()
    token = c_gen_token(ws, keys)
    end = time()
    print(f"gen token: {end-start} s")

    start = time()
    enc_res = s_search(token, edb, len(ws))
    end = time()
    print(f"search: {end-start} s")

    start = time()
    res = c_resolve(enc_res, keys)
    end = time()
    print(f"dec to get res: {end-start} s")
    print(f"res:{res}")
