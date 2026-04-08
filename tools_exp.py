from Utils.SHVE import *
from Utils.SSPE_XF import *
from Utils.BF import *
from time import time
from random import sample
from Utils.fileUtils import *
import pickle

from Utils.log import get_logger

# logger1: 记录加密阶段的实验结果
logger1 = get_logger("./log/tools_enc_exp.log")
# logger2: 记录查询阶段的实验结果
logger2 = get_logger("./log/tools_query_exp.log")

"""
测试“对集合 Y 建立加密结构”时的时间与存储开销。

这里比较两种工具：
1. Doris 中使用的 SSPE_XF
2. HXT 中使用的 SHVE（通过 Bloom Filter 表示集合）

n: |Y|
"""


def enc_test(n: int):
    # 随机生成一个大小为 n 的集合 Y，元素统一为 8 字节随机串。
    database = set([get_random_bytes(8) for _ in range(n)])

    # ---------- SSPE_XF ----------
    # setup() 只初始化主密钥和空的 XOR Filter，不计入 enc_time。
    sspe = SSPE_XF()
    msk_bf = sspe.setup(n)

    # enc_time 从真正开始把 Y 编码进 XOR Filter 时开始计时。
    start = time()
    sspe.enc(msk_bf, database)
    # 在 SSPE_XF 中，密文结构就是构造完成后的 XOR Filter。
    ct = msk_bf.xf
    end = time()
    # XOR Filter 的每个槽位固定保存 32 字节。
    ct_size = len(ct.array) * 32
    enc_time = end - start

    logger1.info(f"SSPE_XF,{n},{enc_time:.5f},{ct_size}")

    # ---------- SHVE ----------
    # SHVE 这里先把 Y 插入 Bloom Filter，再对 Bloom 向量做加密。
    hve = SHVE()
    msk = hve.setup()

    start = time()
    bf1 = BF(n, pow(10, -6))
    bf1.add_all(database)
    res_c = hve.encBF(msk, bf1)
    end = time()
    # SHVE 密文是一个 bytes 列表，每个分量固定为 32 字节。
    res_size = len(res_c) * 32
    enc_time = end - start

    logger1.info(f"SHVE,{n},{enc_time:.5f},{res_size}")


def cal_comm_cost(object):
    # 用 pickle 估算对象序列化后的通信大小。
    # 这反映的是实验代码中的 Python 对象大小，不是论文里的理论 bit 数。
    tmp = pickle.dumps(object)
    return len(tmp)


"""
对集合 X 生成查询 token，并测试：
1. token 生成时间
2. token 通信大小
3. 服务端查询时间

n: |Y|
m: |X|
"""


def keyGen_and_query_test(n: int, m_lst: List[int]):
    # 固定一个全集 Y，后续查询集合 X 都从 Y 中随机抽样得到。
    # 因此每轮实验中都有 X ⊆ Y，最终查询结果应为 True。
    database = set([get_random_bytes(8) for _ in range(n)])

    # ---------- 预先构造 SSPE_XF 密文结构 ----------
    sspe = SSPE_XF()
    msk_bf = sspe.setup(n)
    sspe.enc(msk_bf, database)
    ct = msk_bf.xf

    # ---------- 预先构造 SHVE 密文结构 ----------
    hve = SHVE()
    msk = hve.setup()
    bf1 = BF(n, pow(10, -6))
    bf1.add_all(database)
    res_c = hve.encBF(msk, bf1)

    # 对每个 m 重复 5 次并取平均，减少随机波动。
    times = 5
    for m in m_lst:
        # SSPE_XF 的统计量
        key_gen_time1 = 0
        key_size1 = 0
        query_time1 = 0

        # SHVE_BF 的统计量
        key_gen_time3 = 0
        res_size3 = 0
        query_time3 = 0

        for _ in range(times):
            # 从全集 Y 中抽取一个大小为 m 的子集 X。
            sub_database = sample(database, m)

            # ---------- SSPE_XF ----------
            # 查询方生成查询密钥。
            start = time()
            key = sspe.keyGen(msk_bf.msk, sub_database)
            end = time()
            key_size1 += cal_comm_cost(key)
            key_gen_time1 += end - start

            # 服务端执行一次 dec()，判断 X 是否被 Y 覆盖。
            # query_time1 只统计这一次 dec() 调用本身的时间。
            start = time()
            res = sspe.dec(key, ct)
            end = time()
            query_time1 += end - start
            assert res == True

            # ---------- SHVE + Bloom Filter ----------
            # 先把查询集合 X 映射成 Bloom Filter 的位置集合，
            # 再由这些位置生成 SHVE 查询 token。
            start = time()
            bf2 = BF(n, pow(10, -6))
            pos_set = get_pos_set(sub_database, bf2.k, bf2.m)
            res_pos = hve.keyGenFromBFPos(msk, pos_set)
            end = time()
            key_gen_time3 += end - start
            res_size3 += cal_comm_cost(res_pos)

            # 服务端执行一次 SHVE 查询。
            # query_time3 只统计这一次 query() 调用本身的时间。
            start = time()
            res = hve.query(res_c, res_pos)
            end = time()
            query_time3 += end - start
            assert res == True

        # 记录当前 m 下的平均值。
        logger2.info(
            f"SSPE_XF,{n},{m},{key_gen_time1/times:.5f},{key_size1//times},{query_time1/times:.5f}"
        )
        logger2.info(
            f"SHVE_BF,{n},{m},{key_gen_time3/times:.5f},{res_size3//times},{query_time3/times:.5f}"
        )


if __name__ == "__main__":
    start = time()
    """
    实验 1：比较两种工具在加密阶段的时间和密文大小。
    """
    logger1.info("tool_name,n,enc_time(s),ct_size(B)")
    # 全集 Y 的大小从 10^2 增加到 10^6。
    Y_size_lst = [pow(10, i) for i in range(2, 7)]
    for n in Y_size_lst:
        enc_test(n)

    """
    实验 2：固定 |Y| = 10^4，改变查询集合 |X|，
    比较 token 生成时间、token 大小和查询时间。
    """
    logger2.info("tool_name,n,m,key_gen_time(s),key_size(B),query_time(s)")
    # 查询集合 X 的大小从 1000 增加到 7000。
    X_size_lst = [i * 1000 for i in range(1, 8)]
    keyGen_and_query_test(pow(10, 4), X_size_lst)

    end = time()
    print(f"tools exp use time:{end-start} s")
