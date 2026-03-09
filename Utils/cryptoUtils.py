from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac
from hashlib import sha256

'''
crypto
'''
def prf(k:bytes,m)->bytes:
    if not (type(m) is bytes):
        m = bytes(m, 'utf-8')
    p = hmac.new(k,m,digestmod=sha256)
    return p.digest()

def hash(m)->bytes:
    if not (type(m) is bytes):
        m = bytes(m, 'utf-8')
    return sha256(m).digest()

# hash_length作用：接受一个消息 msg 和一个整数 int，并返回一个经过多次哈希操作后的哈希值
def hash_length(msg, int: int):
    # 它首先对 msg 进行哈希处理，
    # 然后进入一个循环 int 次，
    # 循环中每次将一个由 i 构成的字节串添加到 msg 后，再进行哈希操作，并将结果累加
    h = hash(msg)
    i = 0
    while i < int:
        h = hash(msg+bytes(str(i), "utf-8"))+h
        i = i+1
    return h

# AES/CBC
def AES_enc(key: bytes, m) -> bytes:
    if not (type(m) is bytes):
        m = bytes(m, 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    c = cipher.encrypt(pad(m, AES.block_size))
    return iv+c


def AES_dec(key: bytes, c: bytes) -> bytes:
    iv = c[:AES.block_size]
    c = c[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    m = cipher.decrypt(c)
    return unpad(m, AES.block_size)
