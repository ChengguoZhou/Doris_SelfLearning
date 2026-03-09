from Crypto.Random import get_random_bytes
from typing import List
import struct
from Utils.cryptoUtils import prf, AES_enc, AES_dec
from Utils.pbcUtils import pbcUtil
from Utils.TSet import TSet, genStag, cal_size
from Utils.BF import BF
from Utils.fileUtils import read_index
from dataclasses import dataclass


@dataclass
class PARAMS:
    # ks：给结果加密/解密 (s = symmetric)
    ks: bytes = get_random_bytes(16)
    # kx：给关键词生成和 XSet 相关的陷门 (x = xSet)
    kx: bytes = get_random_bytes(16)
    # ki：给文档 id 映射成群里的元素 （i = id）
    ki: bytes = get_random_bytes(16)
    # kz：生成每条记录（w, i）位置相关的随机量 z (z = position)
    kz: bytes = get_random_bytes(16)
    # kt：TSet 建好后得到的密钥 (t = TSet)
    kt: bytes = None


pbc = pbcUtil()


class EDB:
    def __init__(self, n: int, p: float, k: int) -> None:
        """
        n: (w,id) 对的总数
        p: 布隆过滤器误判率
        k: TSet扩展因子
        """
        # 初始化两个加密索引
        # 候选集索引TSet（第一个关键词索引的结果）
        self.tset = TSet(n, k)
        # XSet，用布隆过滤器存储
        self.xset = BF(n, p)

    # EDBSetup() 建库
    """
        1、读入倒排索引 w -> [id]
        2、对每个关键词 w，生成结果加密 key ke 和 XSet 陷门 xtrap
        3、对每个文档 id，算出 xind、位置随机量 z、以及掩码值 y
        4、把 [len(y) | y | Enc_ke(id)] 放进 TSet
        5、把 xtag(ind, w) 放进 XSet
    """
    def EDBSetup(self, fpath_wid: str, keys: PARAMS):
        T = dict()

        # 读入倒排索引
        # dct_wid = {w1: [id1, id2, ...], w2: [id1, id2, ...], ...}
        dct_wid = read_index(fpath_wid)

        # 遍历每个关键词
        # w: 一个关键词 - ids: 包含这个关键词的所有文档 id
        for w, ids in dct_wid.items():
            # 由主密钥ks和关键词w导出的对称加密密钥 ke
            # （ke作用是加密关键词对应的id）
            ke = prf(keys.ks, w)
            # xtrap： 由kx和关键词w导出的群/域元素，用在XSet
            # xtrap形象化的理解 关键词在XSet的“表示”
            xtrap = pbc.prfToZr(keys.kx, w)

            # 处理这个关键词在TEst对应的每个文档id
            t = []
            # i: 第几个结果的位置编号， 即（关键词， 第i个结果）
            for i in range(len(ids)):
                # ind: 真正的文档 id
                ind = ids[i]
                # 把文档id映射到群/域Zr里的一个元素
                # xind ：文档 id 对应的群/域元素
                xind = pbc.prfToZr(keys.ki, ind)
                # 关键词w + 它的第i个结果 得到一个唯一位置相关随机量z
                z = pbc.prfToZr(keys.kz, w + str(i))
                # ~z : z的逆元
                # 形象理解为 y = xind / z
                y = pbc.mul2Zr(xind, ~z)
                # 把群元素转成字符串，方便拼接存储
                y = pbc.Zr2Bytes(y)
                # e : 用 ke 加密真实文档 id，把加密结果拼到 element 里
                e = AES_enc(ke, ind)
                # struct.pack("H", len(y)) 把len(y)打包成2字节的二进制数据
                # element = [2字节长度] + [y的字符串] + [加密后文档id e]
                element = struct.pack("H", len(y)) + y + e
                # 这个关键词 w 的第 i 条记录，被编码成一个 element，放入TSet
                t.append(element)
                # 同时构造XSet
                # 把文档id信息xind 和 关键词信息信息xtrap结合起来，生成标签xtag，放入XSet
                xtag = pbc.gToPower2(xind, xtrap)
                self.xset.add(str(xtag))
            # 一轮处理完一个关键词 w
            T[w] = t
        # 把整个T交给TSet建结构，并返回kt
        keys.kt = self.tset.setup(T)


"""
Complete search process
"""

# search（） 查询
# ws = word search，即关键词列表; List[str]表示 ws 是一个由字符串组成的列表
# edb = 加密数据库； EDB表示EDB类
# key = 密钥集合PARAMS的一个实例
# 返回值 ：返回一个整数列表，表示符合搜索条件的文档 ID
def search(ws: List[str], edb: EDB, keys: PARAMS) -> List[int]:
    # 用第一个词 w1 生成 stag,去 TSet 取出候选列表 t
    # t的每个元素像 [len(y) | y | e]
    w1 = ws[0]
    ke = prf(keys.ks, w1)
    stag = genStag(keys.kt, w1)
    t = edb.tset.retrive(stag)

    # 第二步： 拆每个候选元素
    end = []
    for i, item in enumerate(t):
        # 格式符"H"表示无符号短整型，通常占两个字节； item[:2]提取item的前两个字节
        # struct。unpack()函数返回的是一个包含一个元素的元组，例如(5,)
        (l,) = struct.unpack("H", item[:2])
        # y = 从item中提取出从第 2 个字节开始，到第 2 + l 个字节的数据
        y = item[2 : 2 + l]
        # 将 y 转换成群 Zr 中的一个元素
        y = pbc.bytes2Zr(y)
        # e =
        e = item[2 + l :]

        # 对剩余关键词逐个测试
        flag = 0
        for j in range(1, len(ws)):
            # 关键词w1 + 它的第i个结果生成z
            z = pbc.prfToZr(keys.kz, w1 + str(i))
            # 为剩余关键词w2, w3生成xtrap
            xtrap = pbc.prfToZr(keys.kx, ws[j])
            # 生成xtoken 理解成xtoken = z ^ xtrap
            xtoken = pbc.gToPower2(z, xtrap)
            # 验证xtoken和y组合后是否存在于XSet中
            if str(pbc.pow(xtoken, y)) in edb.xset:
                # 如果匹配，增加标志
                flag += 1
        # 都匹配才能解密
        if flag == len(ws) - 1:
            ind = AES_dec(ke, e)
            end.append(ind)
    return end


"""
Each step of the search process
"""

# c_gen_stag()：生成查询标识 stag
def c_gen_stag(ws: List[str], keys: PARAMS):
    return genStag(keys.kt, ws[0])

# s_retrive_stag(): 从 TSet 中检索候选文档
def s_retrive_stag(tset: TSet, stag: bytes):
    return tset.retrive(stag)

# c_gen_xtoken()：生成每个候选文档的 xtoken，即关键词在文档中的“陷门”表示
def c_gen_xtoken(t_len: int, ws: List[str], keys: PARAMS):
    xtoken = [] * t_len
    for i in range(t_len):
        xtoken_i = []
        w1 = ws[0]
        for j in range(1, len(ws)):
            z = pbc.prfToZr(keys.kz, w1 + str(i))
            xtrap = pbc.prfToZr(keys.kx, ws[j])
            xtoken_ij = pbc.gToPower2(z, xtrap)
            xtoken_i.append(xtoken_ij)
        xtoken.append(xtoken_i)
    return xtoken

# s_get_es(): 根据 xtoken 检查每个候选文档是否匹配所有关键词，并返回加密的文档 ID
def s_get_es(xtoken, xset: BF, t):
    es = []
    for i, item in enumerate(t):
        (l,) = struct.unpack("H", item[:2])
        y = item[2 : 2 + l]
        y = pbc.bytes2Zr(y)
        e = item[2 + l :]

        flag = 0
        xtoken_i = xtoken[i]
        length = len(xtoken_i)
        for j in range(length):
            if str(pbc.pow(xtoken_i[j], y)) in xset:
                flag += 1
        if flag == length:
            es.append(e)
    return es

# c_decrypt_e(): 该函数通过AES_dec() 解密所有符合条件的文档 ID
def c_decrypt_e(es: List[bytes], ws: List[str], keys: PARAMS):
    ke = prf(keys.ks, ws[0])
    res = [AES_dec(ke, e) for e in es]
    return res


if __name__ == "__main__":
    from time import time
    import pickle

    """
    test case
    """
    # small database
    filename = "./data/enron_inverted0.csv"
    ws = ["trade", "buyer"]  # 13,14
    ws = ["trade", "buyer", "juan", "gas"]
    n = 100
    p = 0.0001
    k = 2

    """
    edb setup 
    """
    start = time()
    keys = PARAMS()
    edb = EDB(n, p, k)
    edb.EDBSetup(filename, keys)
    end = time()
    print(f"edb setup: {end-start} s")
    # tset_size = cal_size(edb.tset)
    # print(f"tset size(cal lenth): {tset_size/1024} KB")
    # tset_size = len(pickle.dumps(edb.tset))
    # print(f"tset size(dump)     : {tset_size/1024} KB")
    # xset_size = len(edb.xset) // 8
    # print(f"xset size(cal lenth): {xset_size/1024} KB")
    # xset_size = len(pickle.dumps(edb.xset))
    # print(f"xset size(dump)     : {xset_size/1024} KB")

    """
    Complete search process
    """
    inds = search(ws, edb, keys)
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
    xtoken = c_gen_xtoken(len(t), ws, keys)
    end = time()
    print(f"gen xtoken: {end-start} s")

    start = time()
    es = s_get_es(xtoken, edb.xset, t)
    end = time()
    print(f"get enc res: {end-start} s")

    start = time()
    res = c_decrypt_e(es, ws, keys)
    end = time()
    print(f"dec to get res: {end-start} s")
    print(f"res:{res}")
