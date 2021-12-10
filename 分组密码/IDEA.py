# 循环左移
def rol(n, m):
    return ((n << m) | (n >> (128 - m))) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


# 求加密子密钥
def sub_key(key):
    res = []
    if type(key) != bytes:
        key = bytes(key, encoding='utf8')
    for i in range(7):
        for j in range(8):
            res.append(int.from_bytes(key[j * 2:j * 2 + 2], 'big'))
        key = rol(int.from_bytes(key, 'big'), 25)
        key = key.to_bytes(length=16, byteorder='big')
    return res


# 模乘
def modMultiply(x, y):
    return (x * y) % 65537


# 模加
def modAdd(x, y):
    return (x + y) % 65536


# 求乘法逆元
# def inv(d, k):
#     return gmpy2.invert(d, k)


# 扩展欧几里得求逆元
def exgcd(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = exgcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q


def inv(a, p):
    x, y, q = exgcd(a, p)
    if q != 1:
        print("inv_error")
        return -1
    else:
        return (x + p) % p


# 求解密子密钥
def subDkey(key):
    subkey = sub_key(key)
    res = [-1] * 52
    # 乘法逆
    res[0] = inv(subkey[48], 65537)
    # 加法逆
    res[1] = (65536 - subkey[49]) % 65536
    res[2] = (65536 - subkey[50]) % 65536
    res[3] = inv(subkey[51], 65537)
    for i in range(1, 9):
        res[i * 6] = inv(subkey[(8 - i) * 6], 65537)
        res[i * 6 + 2] = (65536 - subkey[(8 - i) * 6 + 1]) % 65536
        res[i * 6 + 1] = (65536 - subkey[(8 - i) * 6 + 2]) % 65536
        res[i * 6 + 3] = inv(subkey[(8 - i) * 6 + 3], 65537)
    for i in range(8):
        res[i * 6 + 4] = subkey[(7 - i) * 6 + 4]
        res[i * 6 + 5] = subkey[(7 - i) * 6 + 5]
    return res


# 对一个分组长度的密文进行加密
def Encrypto(key, plaintext):
    subKey = sub_key(key)
    if type(plaintext) != bytes:
        plaintext = bytes(plaintext, encoding='utf8')
    p = []
    for i in range(4):
        p.append(int.from_bytes(plaintext[i * 2:i * 2 + 2], 'big'))
    # 8轮变换
    for i in range(8):
        temp1 = modMultiply(subKey[i * 6], p[0])
        temp2 = modAdd(subKey[i * 6 + 2], p[2])
        temp3 = modAdd(subKey[i * 6 + 1], p[1])
        temp4 = modMultiply(subKey[i * 6 + 3], p[3])
        temp5 = temp1 ^ temp2
        temp6 = temp3 ^ temp4
        temp7 = modMultiply(temp5, subKey[i * 6 + 4])
        temp8 = modAdd(temp7, temp6)
        temp9 = modMultiply(temp8, subKey[i * 6 + 5])
        temp10 = modAdd(temp7, temp9)
        temp11 = temp10 ^ temp4
        temp12 = temp10 ^ temp3
        temp13 = temp1 ^ temp9
        temp14 = temp2 ^ temp9
        p[0] = temp13
        p[1] = temp14
        p[2] = temp12
        p[3] = temp11
    # 输出变换
    c1 = modMultiply(p[0], subKey[6 * 8])
    c2 = modAdd(p[2], subKey[6 * 8 + 1])
    c3 = modAdd(p[1], subKey[6 * 8 + 2])
    c4 = modMultiply(p[3], subKey[6 * 8 + 3])
    res = c4 + c3 * (1 << 16) + c2 * (1 << 32) + c1 * (1 << 48)
    res = res.to_bytes(length=8, byteorder='big')
    return res


# 解密一个分组长度的密文
def Decrypto(key, str):
    Dkey = subDkey(key)
    s = []
    for i in range(4):
        s.append(int.from_bytes(str[i * 2:i * 2 + 2], 'big'))
    # 8轮变换
    for i in range(8):
        temp1 = modMultiply(Dkey[i * 6], s[0])
        temp2 = modAdd(Dkey[i * 6 + 2], s[2])
        temp3 = modAdd(Dkey[i * 6 + 1], s[1])
        temp4 = modMultiply(Dkey[i * 6 + 3], s[3])
        temp5 = temp1 ^ temp2
        temp6 = temp3 ^ temp4
        temp7 = modMultiply(temp5, Dkey[i * 6 + 4])
        temp8 = modAdd(temp7, temp6)
        temp9 = modMultiply(temp8, Dkey[i * 6 + 5])
        temp10 = modAdd(temp7, temp9)
        temp11 = temp10 ^ temp4
        temp12 = temp10 ^ temp3
        temp13 = temp1 ^ temp9
        temp14 = temp2 ^ temp9
        s[0] = temp13
        s[1] = temp14
        s[2] = temp12
        s[3] = temp11
    # 输出变换
    c1 = modMultiply(s[0], Dkey[6 * 8])
    c2 = modAdd(s[2], Dkey[6 * 8 + 2])
    c3 = modAdd(s[1], Dkey[6 * 8 + 1])
    c4 = modMultiply(s[3], Dkey[6 * 8 + 3])
    res = int(c4 + c3 * (1 << 16) + c2 * (1 << 32) + c1 * (1 << 48))
    res = res.to_bytes(length=8, byteorder='big')
    return res


def EnC(key, plaintext):
    p_len = len(bytes(plaintext, encoding='utf8'))
    num = 0
    add = 0
    if p_len % 8 == 0:
        num = int(p_len / 8)
    else:
        add = 8 - (p_len % 8)
        num = int((p_len + add) / 8)
    # 不足64位长度的分组用\0x20填充，因为\0x20为空格所以解密时不做处理
    p_add = bytes([32] * add)
    p = bytes(plaintext, encoding='utf8')
    p += p_add
    res = bytes()
    for i in range(num):
        res += Encrypto(key, p[i * 8:i * 8 + 8])
    return res


def DeC(key, str):
    if type(str) != bytes:
        print("输入密文必须为bytes类型")
        return -1
    s_len = len(str)
    num = int(s_len / 8)
    res = bytes()
    for i in range(num):
        res += Decrypto(key, str[i * 8:i * 8 + 8])
    return res


def main():
    # 128位密钥16进制表示
    # key = bytes.fromhex("12345678123456781234567812345678")
    # 长度为16的ASCII字符串,使得密钥为128位
    key = "welcome_to_CUMT!"
    # 任意加密字符串
    plaintext = "密码学真是太有趣了！😅"
    # 加密
    mystr = EnC(key, plaintext)
    print("加密后的数据为(16进制表示)")
    print(mystr.hex())
    # 0279a5e7f85ff616624e99b256fb566a53350145aa9c5dfd74926b38f31934ab71b95069af41b1a9
    # 解密
    print("解密后的数据为(utf-8编码)")
    print(str(DeC(key, mystr), encoding="utf-8"))


if __name__ == '__main__':
    main()
