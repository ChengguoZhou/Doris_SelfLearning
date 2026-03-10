# 从 pypbc 导入双线性对库里的几个核心对象
# Element: 群元素/域元素的通用表示 G1:一个乘法群 Zr:一个有限域/指数空间
from pypbc import Element, G1, Zr
# 导入 pairing 参数，pairing 里保存了双线性群的系统参数，后面创建 Element 时都要用到它
from .cfg import pairing
# 导入前面学过的 prf
from .cryptoUtils import prf
# long_to_bytes:整数 -> bytes bytes_to_long:bytes -> 整数
# 后面做 Zr 和 bytes 的互转会用到
from Crypto.Util.number import long_to_bytes, bytes_to_long

#  pbcUtils定义一个工具类，专门封装双线性群/有限域上的常用操作
class pbcUtil:
    # 初始化 pbcUtil 对象
    def __init__(self) -> None:
        # 生成一个随机群生成元g，后面很多g^x形式的运算都基于它
        self.g = self._gen_g()

    # 随机生成一个 G1 群里的元素,这里把它当作生成元g来使用(它是所有指数表达式的底)
    def _gen_g(self):
        # pairing: 系统参数, G1: 指定元素属于G1群
        return Element.random(pairing, G1)

    # 把“密钥 k + 消息 m”映射到 Zr 中的一个元素（为了后续做指数和乘法运算的需要）
    def prfToZr(self, k: bytes, m: str) -> Element:
        # 先用 PRF 得到一个伪随机字节串 c
        c = prf(k, m)
        # 再把字节串 c 映射成 Zr 里的元素，返回类型是 Element
        return Element.from_hash(pairing, Zr, c)

    # 计算g^n 其中n 是 Zr 中的元素，结果属于G1群
    def gToPower(self, n: Element) -> Element:
        # self.g是底, n是指数， 返回G1中的群元素
        return Element(pairing, G1, self.g**n)

    # pow(g,n*m)，n 和 m 都是 Zr 中的元素，结果属于 G1
    def gToPower2(self, n: Element, m: Element) -> Element:
        # 先算 n*m，再计算 g 的这个指数幂
        return Element(pairing, G1, self.g**(n*m))

    # Convert the elements in Zr to bytes type
    def Zr2Bytes(self, ele: Element) -> bytes:
        # 先把 ele 转成字符串，再按 16 进制解释成整数，最后把整数转成 bytes
        return long_to_bytes(int(str(ele), 16))

    # Convert bytes type data to element in Zr
    def bytes2Zr(self, bstr: bytes) -> Element:
        # 先把 bytes 转成整数，再用这个整数构造一个 Zr 元素
        return Element(pairing, Zr, value=bytes_to_long(bstr))

    # n*m（普通乘法）
    def mul2Zr(self, n: Element, m: Element) -> Element:
        return Element(pairing, Zr, n*m)

    # pow(n,m)
    def pow(self, n: Element, m: Element) -> Element:
        return Element(pairing, G1, n**m)
