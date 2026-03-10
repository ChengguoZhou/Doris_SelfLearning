import pickle
from Crypto.Random import get_random_bytes
from typing import List
from Utils.cryptoUtils import prf, AES_enc, AES_dec
from Utils.TSet import TSet, cal_size, genStag
from Utils.SSPE_XF import SSPE_XF, MSK
from Utils.fileUtils import read_index
from dataclasses import dataclass


@dataclass
class PARAMS:
    ke: bytes = get_random_bytes(16)
    kx: bytes = get_random_bytes(16)
    kt: bytes = None


sspe = SSPE_XF()


class EDB:
    def __init__(self, n: int, k: int) -> None:
        self.tset = TSet(n, k)
        self.ct = None  # sspe

    def setup(self, fpath_wid: str, fpath_idw: str, keys: PARAMS) -> MSK:
        # 关键词 -> 文档列表
        dct_wid = read_index(fpath_wid)
        # 文档列表 -> 关键词
        dct_idw = read_index(fpath_idw)

        # 初始化 TSet 和 XSet
        T = dict()
        xset = set()

        # 遍历每个关键词
        for w, ids in dct_wid.items():
            # t: 关键词在TSet中的列表
            t = []
            i = 1
            # 给每个关键词派生一个AES密钥
            kw = prf(keys.ke, w)
            # 对关键词w下的每个文档 id
            for id in ids:
                # 用关键词相关密钥 kw 加密，然后准备放进 TSet
                e = AES_enc(kw, id)
                # Doris特有的：找出当前文档id包含的所有关键词，
                # 然后把当前主关键词w自己删掉
                ws = dct_idw.get(id).copy()  # Copy to prevent the w from being deleted
                ws.remove(w)

                # Doris_XF的关键
                # 对于关键词w的第i个候选文件，如果该文档还包含另一个关键词 w_tmp，
                # 那就生成一个标签 xtag = PRF(kx, w || w_tmp || i)，放入XSet
                for w_tmp in ws:
                    # TODO: Correctness testing
                    # print(w,w_tmp,id)
                    xtag = prf(keys.kx, w + w_tmp + str(i))
                    xset.add(xtag)
                t.append(e)
                i += 1
            # Doris方案TSet只负责存储该关键词w下的加密候选结果
            # 而OXT方案TSet为len(y) | y | e， 其中近似理解y = xind / z，
            # 而xind是文档id映射到群Zr的结果， z是 （关键词w,第i个候选文件） 生成的随机量
            T[w] = t
        keys.kt = self.tset.setup(T)

        # 初始化SSPE
        msk_bf = sspe.setup(len(xset))
        # TODO: Correctness testing
        # print(f"xset element number: {len(xset)}")
        # 把 xset 编码/加密进去
        sspe.enc(msk_bf, xset)
        # 服务器端保存的查询结构（在Doris_XF中，self.ct相当于OXT中的xset/BF一侧）
        self.ct = msk_bf.xf

        return msk_bf.msk


"""
Complete search process
"""


def search(msk: MSK, ws: List[str], edb: EDB, keys: PARAMS) -> List[int]:
    # Tset
    # 第一个关键词 w1
    w1 = ws[0]
    # 派生解密密钥 ke
    ke = prf(keys.ke, w1)
    # 生成 stag
    stag = genStag(keys.kt, w1)
    # 去 TSet 取候选 t
    t = edb.tset.retrive(stag)

    # Xset
    end = []
    for i, e in enumerate(t):
        QSet = []
        # 遍历剩余关键词
        for j in range(1, len(ws)):
            # 第一个查询关键词 + 第j个查询关键词 + 第 i+1 个候选文件
            # 注意：w + w_tmp 只说明“有这种关系”，w + w_tmp + i 才说明“第 i 个候选有这种关系”
            qtag = prf(keys.kx, w1 + ws[j] + str(i + 1))
            QSet.append(qtag)

        # QSet：想检查的条件集合 sspe.keyGen：把条件集合变成一个查询token
        xtoken = sspe.keyGen(msk, QSet)
        # sspe.dec 去服务器保存的结构里判断这些条件是否都满足，只有全部满足的候选，才会被解密并加入最终结果
        if sspe.dec(xtoken, edb.ct) == True:
            ind = AES_dec(ke, e)
            end.append(ind)
    return end


"""
every step
"""


def c_gen_stag(ws: List[str], keys: PARAMS):
    return genStag(keys.kt, ws[0])


def s_retrive_stag(tset: TSet, stag: bytes):
    return tset.retrive(stag)


def c_gen_xtoken(msk: MSK, t_len: int, ws: List[str], keys: PARAMS):
    xtoken = []
    w1 = ws[0]
    for i in range(t_len):
        QSet = []
        for j in range(1, len(ws)):
            qtag = prf(keys.kx, w1 + ws[j] + str(i + 1))
            QSet.append(qtag)

        key = sspe.keyGen(msk, QSet)
        xtoken.append(key)
    return xtoken


def s_get_es(xtoken, t, ct) -> List[bytes]:
    es = []
    for i, e in enumerate(t):
        # start = time()
        s = xtoken[i]
        if sspe.dec(s, ct) == True:
            es.append(e)
        # end = time()
        # print(end-start)
    return es


def c_decrypt_e(es: List[bytes], ws: List[str], keys: PARAMS):
    ke = prf(keys.ke, ws[0])
    res = [AES_dec(ke, e) for e in es]
    return res


if __name__ == "__main__":
    from time import time

    """
    test case
    """
    # small database
    f_wid = "./data/enron_inverted0.csv"
    f_idw = "./data/enron_index0.csv"
    ws = ["trade", "buyer"]  # 13,14
    ws = ["trade", "buyer", "juan", "gas"]
    n = 100
    k = 2

    """
    edb setup 
    """
    start = time()
    keys = PARAMS()
    edb = EDB(n, k)
    msk = edb.setup(f_wid, f_idw, keys)
    end = time()
    print(f"edb setup: {end-start} s")
    # tset_size = cal_size(edb.tset)
    # print(f"tset size(cal lenth): {tset_size/1024} KB")
    # tset_size = len(pickle.dumps(edb.tset))
    # print(f"tset size(dump)     : {tset_size/1024} KB")
    # xset_size = len(edb.ct) *32
    # print(f"xset size(cal lenth): {xset_size/1024} KB")
    # xset_size = len(pickle.dumps(edb.ct))
    # print(f"xset size(dump)     : {xset_size/1024} KB")

    """
    Complete search process
    """
    inds = search(msk, ws, edb, keys)
    print(inds)

    """
    Each step of the search process
    """
    start = time()
    stag = c_gen_stag(ws, keys)
    end = time()
    print(f"gen stag: {end-start} s")

    start = time()
    t = s_retrive_stag(edb.tset, stag)
    end = time()
    print(f"retrive stag: {end-start} s")

    start = time()
    xtoken = c_gen_xtoken(msk, len(t), ws, keys)
    end = time()
    print(f"gen xtoken: {end-start} s")

    start = time()
    es = s_get_es(xtoken, t, edb.ct)
    end = time()
    print(f"get es: {end-start} s")

    start = time()
    res = c_decrypt_e(es, ws, keys)
    end = time()
    print(f"dec to get res: {end-start} s")
    print(f"res:{res}")
