# 从 PyCryptodome 导入 AES 对称加密算法
from Crypto.Cipher import AES
# 导入填充和去填充函数
# 因为 AES 一次只能处理固定长度的块
from Crypto.Util.Padding import pad, unpad
# 导入 HMAC 模块
# 后面 prf() 用它实现“带密钥的伪随机函数”
import hmac
# 导入 SHA-256 哈希函数
# 后面 hash() 和 prf() 都会用到
from hashlib import sha256

'''
crypto
'''
# 用密钥 k 和输入 m 计算一个固定长度的伪随机输出
def prf(k:bytes,m)->bytes:
    # 如果m 不是 bytes 类型，就把它转成 utf-8 编码的字节串
    if not (type(m) is bytes):
        m = bytes(m, 'utf-8')
    # 用 HMAC-SHA256 计算带密钥摘要, 其中k：密钥 m：消息
    # digestmod=sha256： 指定底层哈希算法SHA-256
    p = hmac.new(k,m,digestmod=sha256)
    # 返回最终摘要结果
    # digest() 返回原始二进制字节串
    return p.digest()

# 定义普通哈希函数，输入 m 可以是字符串或 bytes，返回 SHA-256 哈希值（bytes）
def hash(m)->bytes:
    # 如果 m 不是 bytes，就转成 utf-8 编码字节串
    if not (type(m) is bytes):
        m = bytes(m, 'utf-8')
    # 对 m 做 SHA-256 哈希，返回原始二进制摘要
    return sha256(m).digest()

# hash_length作用：接受一个消息 msg 和一个整数 int，并返回一个经过多次哈希操作后的哈希值
def hash_length(msg, int: int):
    # 它首先对 msg 进行哈希处理，
    # 然后进入一个循环 int 次，
    # 循环中每次将一个由 i 构成的字节串添加到 msg 后，例如 msg||"0"、msg||"1"、msg||"2"，再进行哈希操作，并将结果累加
    h = hash(msg)
    i = 0
    while i < int:
        h = hash(msg+bytes(str(i), "utf-8"))+h
        i = i+1
    return h

# 定义 AES 加密函数，key： AES密钥， m是明文（字符串或bytes），返回密文 bytes
# AES/CBC
def AES_enc(key: bytes, m) -> bytes:
    # 如果明文m 不是 bytes，就把它转成 utf-8 编码字节串
    if not (type(m) is bytes):
        m = bytes(m, 'utf-8')
    # 创建AES加密器，模式使用 CBC（Cipher Block Chaining）
    # 这里没有手动传 iv，库会自动随机生成一个 iv
    cipher = AES.new(key, AES.MODE_CBC)
    # 取出自动生成的 iv，iv 是初始化向量，CBC 模式必须使用
    iv = cipher.iv
    # 先对明文 m 做填充 pad，因为 AES 要求输入长度是 block_size 的整数倍
    # 然后再进行加密，得到密文 c
    c = cipher.encrypt(pad(m, AES.block_size))
    # 返回 iv 和密文拼接结果，这样解密时就能先取出 iv
    return iv+c

# 定义 AES 解密函数，key 是 AES 密钥，c是密文，格式应该是 iv + 真正密文，返回解密后的明文 bytes
def AES_dec(key: bytes, c: bytes) -> bytes:
    # 取密文前 16 字节作为 iv
    iv = c[:AES.block_size]
    # 剩下部分才是真正的 AES 密文
    c = c[AES.block_size:]
    # 用同样的 key 和取出的 iv, 重新创建 CBC 模式解密器
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # 对密文 c 做解密，得到的还是“带填充”的明文
    m = cipher.decrypt(c)
    # 去掉填充，返回原始明文
    return unpad(m, AES.block_size)
