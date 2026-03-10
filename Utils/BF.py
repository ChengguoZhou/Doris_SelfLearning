from bitarray import bitarray   # 导入位数组，适合表示布隆过滤器的 0/1 比特位
import math                     # 用来做数学计算，比如 log、ceil
import mmh3                     # MurmurHash3 哈希函数库，用来生成多个哈希位置

# 定义 Bloom Filter 类
class BF(object):
    # n: 预计要插入多少个元素
    # p: 误判率(false positive rate)
    def __init__(self, n: int, p: float):
        # 根据 n 和 p 计算出位数组长度 m 和 哈希函数的个数 k
        m = optimalNumOfBits(n, p)
        k = optimalNumOfHash(n, m)

        # BF array
        # 创建一个长度为 m 的位数组，且所有位置都置 0
        self.bit_array = bitarray(m)
        self.bit_array.setall(0)
        # 保存位数组长度
        self.m = m
        # 保存哈希函数个数
        self.k = k

    # len(bf)： 返回布隆过滤器位数组长度 m
    def __len__(self):
        return self.m

    # iter: 让 BF 对象可以被遍历
    def __iter__(self):
        return iter(self.bit_array)

    # add：插入一个元素
    def add(self, item):
        for seed in range(self.k):
            # 对同一个 item，使用不同 seed 计算多个哈希值
            index = mmh3.hash(item, seed) % self.m
            # 把对应位置置为 1
            self.bit_array[index] = 1
        # 返回 self，方便链式调用
        return self

    # add_all：批量插入多个元素
    def add_all(self, items):
        for item in items:
            self.add(item)

    # __contains__：判断元素是否“在集合中”
    # 查询时if str(pbc.pow(xtoken, y)) in edb.xset: 实际调用的是 edb.xset.__contains__(...)
    def __contains__(self, item):
        # 判断 item 是否“可能在”布隆过滤器中
        out = True
        for seed in range(self.k):
            # 重新算出 item 对应的 k 个位置
            index = mmh3.hash(item, seed) % self.m
            # 只要有一个位置是 0，说明它一定没被插入过
            if self.bit_array[index] == 0:
                out = False
        # 如果所有位置都是 1，则返回 True（表示可能在）
        return out

"""
    optimalNumOfBits(): 计算布隆过滤器位数组长度m
    n: 预计插入的元素个数 p: 目标误判率
    返回: 位数组大小 m
"""
def optimalNumOfBits(n: int, p: float) -> int:
    """
    布隆过滤器经典公式
    m = -{[n*ln(e)]/(ln2)^2}
    """
    return math.ceil(n * (-math.log(p)) / (math.log(2) * math.log(2)))

"""
    optimalNumOfHash(): 计算最优哈希函数个数 k
    n: 预计插入元素个数 m: 位数组长度
    返回: 哈希函数数量 k
"""
def optimalNumOfHash(n: int, m: int) -> int:
    """
    布隆过滤器经典公式：
    k = (m/n)*ln2
    哈希函数数量太少会导致信息稀疏，误报率高
    太多很多位都被反复置 1，也会导致误判率高
    """
    return math.ceil((m / n) * math.log(2))


def from_e_2_k(p: float) -> int:
    """
    根据误判率 p 计算哈希函数个数 k
    结果与 optimalNumOfHash 等价
    但是在这个类的主流程中未被实际使用，作为“补充工具函数”
    """
    k = math.ceil(-(math.log(p, 2)))
    return k


# 返回一组元素在布隆过滤器中会置 1 的所有位置（去重后用 set 存）
def get_pos_set(items, hash_count: int, bf_size: int) -> set:
    pos_set = set()
    for item in items:
        for seed in range(hash_count):
            # 计算该元素在某个 seed 下的哈希位置
            index = mmh3.hash(item, seed) % bf_size
            # 加入集合，自动去重
            pos_set.add(index)
    return pos_set

# 返回一组元素会命中的所有位置，用 list 保存
def get_pos_list(items, hash_count: int, bf_size: int):
    index_set = []
    for item in items:
        for seed in range(hash_count):
            # 计算哈希位置
            index = mmh3.hash(item, seed) % bf_size
            # 如果这个位置还没记录过，就加入列表
            if index not in index_set:
                index_set.append(index)
    return index_set
