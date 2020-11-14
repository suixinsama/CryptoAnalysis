import random
# S盒参数
S_Box = [6,4,12,5,0,7,2,14,1,15,3,13,8,10,9,11]
# P盒参数
P_Box = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]


def gen_K_list(K):
    """
    秘钥编排算法，由一个32比特秘钥生成6个16比特子秘钥
    :param K: 32比特秘钥
    :return: [k0,k1,k2,k3,k4,k5]，6个16比特子秘钥
    """
    Ks = []
    for i in range(6, 0, -1):
        ki = K % (2 ** 16)
        Ks.insert(0, ki)
        K = K >> 4
    return Ks


def pi_s(s_box, ur):
    """
    分组代换操作
    :param s_box:S盒参数
    :param ur:输入比特串，16比特
    :return:输出比特串，16比特
    """
    vr = 0
    for i in range(4):
        uri = ur % (2 ** 4)
        vri = s_box[uri]
        vr = vr + (vri << (4 * i))
        ur = ur >> 4
    return vr


def pi_p(p_box, vr):
    """
    单比特置换操作
    :param p_box:P盒参数
    :param vr:输入比特串，16比特
    :return:输出比特串，16比特
    """
    wr = 0
    for i in range(15, -1, -1):
        vri = vr % 2
        vr = vr >> 1
        wr = wr + (vri << (16 - p_box[i]))
    return wr


def reverse_Sbox(s_box):
    """
    求S盒的逆
    :param s_box:S盒参数
    :return:S盒的逆
    """
    re_box = [-1] * 16
    for i in range(16):
        re_box[s_box[i]] = i
    return re_box


def reverse_Pbox(p_box):
    """
    求P盒的逆
    :param s_box:P盒参数
    :return:P盒的逆
    """
    re_box = [-1] * 16
    for i in range(16):
        re_box[p_box[i] - 1] = i + 1
    return re_box


def do_SPN(x, s_box, p_box, Ks):
    """
    4轮的SPN网络，可以用来进行加密或解密
    :param x: 16比特输入
    :param s_box: S盒参数
    :param p_box: P盒参数
    :param Ks: [k0,k1,k2,k3,k4,k5]，五个16比特子秘钥
    :return: 16比特输出
    """
    wr = x
    for r in range(4):
        ur = wr ^ Ks[r]  # 异或操作
        vr = pi_s(s_box, ur)  # 分组代换
        wr = pi_p(p_box, vr)  # 单比特置换

    ur = wr ^ Ks[4]
    vr = pi_s(s_box, ur)
    y = vr ^ Ks[5]
    return y


def encrypt(K, x):
    """
    根据秘钥K对16比特明文x进行加密
    :param K:32比特秘钥
    :param x:16比特明文
    :return:16比特密文
    """
    Ks = gen_K_list(K)
    return do_SPN(x, S_Box, P_Box, Ks)


def decrypt(K, y):
    """
    根据秘钥K对16比特密文y进行解密。
    :param K:32比特秘钥
    :param y:16比特密文
    :return:16比特明文
    """
    Ks = gen_K_list(K)
    Ks.reverse()  # 秘钥逆序编排
    # 秘钥置换
    Ks[1] = pi_p(P_Box, Ks[1])
    Ks[2] = pi_p(P_Box, Ks[2])
    Ks[3] = pi_p(P_Box, Ks[3])
    Ks[4] = pi_p(P_Box, Ks[4])
    s_rbox = reverse_Sbox(S_Box)  # S盒求逆
    p_rbox = reverse_Pbox(P_Box)  # P盒求逆
    return do_SPN(y, s_rbox, p_rbox, Ks)

def getbits(x,number):
    d = [0xf000,0x0f00,0x00f0,0x000f]
    return (x&d[number-1])>>((4-number)*4)


def diff(K):
	# 差分路径为0x00d0
    diffInput = 0x00f0
    T = []
    for i in range(2**14):
        r = random.randint(1,2**16-1)
        temp = (r,r^diffInput,encrypt(K,r),encrypt(K,r^diffInput))
        if r not in T:
            T.append(temp)
        else:
            i-=1
    # 初始化计数器
    key = []
    count = {}
    for i in range(16):
        for j in range(16):
            temp = (i,j)
            key.append(temp)
            count[temp] = 0
    test = 0
    for t in T:
        #t[0] = x
        #t[1] = x*
        #t[2] = y
        #t[3] = y*
        x = t[0]
        xx = t[1]
        y = t[2]
        yy = t[3]
        if getbits(y,1) == getbits(yy,1) and getbits(y,2) == getbits(yy,2):
            test+=1
            for k in key:
                l1 = k[0]
                l2 = k[1]
                v3 = l1^getbits(y,3)
                v4 = l2^getbits(y,4)
                u3 = reverse_Sbox(S_Box)[v3]
                u4 = reverse_Sbox(S_Box)[v4]
                vv3 = l1^getbits(yy,3)
                vv4 = l2^getbits(yy,4)
                uu3 = reverse_Sbox(S_Box)[vv3]
                uu4 = reverse_Sbox(S_Box)[vv4]
                uuu3 = u3^uu3
                uuu4 = u4^uu4
                if uuu3 == 0b0100 and uuu4 == 0b1000:
                    count[(l1,l2)]+=1
    #找最大的count对应的key
    print(test)
    print(sorted(count.items(),reverse = True,key=lambda x:x[1])[0])

    ## 差分路径为0x0020
    # diffInput = 0x0020
    # T = []
    # for i in range(2000):
    #     r = random.randint(1,2**16-1)
    #     temp = (r,r^diffInput,encrypt(K,r),encrypt(K,r^diffInput))
    #     if r not in T:
    #         T.append(temp)
    #     else:
    #         i-=1
    # count = {}
    # test = 0
    # for i in range(16):
    #     count[i] = 0
    # for t in T:
    #     x = t[0]
    #     xx = t[1]
    #     y = t[2]
    #     yy = t[3]
    #     if getbits(y,1) == getbits(yy,1) and getbits(y,2) == getbits(yy,2) and getbits(y,4) == getbits(yy,4):
    #         test+=1
    #         for k in range(16):
    #             v3 = k^getbits(y,3)
    #             # print(getbits(y,3))
    #             u3 = reverse_Sbox(S_Box)[v3]
    #             vv3 = k^getbits(yy,3)
    #             uu3 = reverse_Sbox(S_Box)[vv3]
    #             d = u3^uu3
    #             if d == 0b0010:
    #                 count[k]+=1
    #找最大的count对应的key
    # print(test)
    # print(sorted(count.items(),reverse = True,key=lambda x:x[1]))

def printlinearTable(K):
    for i in range(16):
        print("%4x"%i,end = '')
    print()
    for a in range(16):
        print("%x"%a,end='')
        for b in range(16):
            count = 0
            for i in range(16):
                j = S_Box[i]
                if (i&a)^(b&j) == 0:
                    count+=1
            print("%4d"%count,end = '')
        print()

def getbit(x,number):
    d = [0b1000,0b0100,0b0010,0b0001]
    return (x&d[number-1])>>((4-number))

def linear(K):
    #线性分析破译1bit密钥
    T = []
    num = 60000
    for i in range(num):
        r = random.randint(1,2**16-1)
        temp = (r,encrypt(K,r))
        if r not in T:
            T.append(temp)
        else:
            i-=1
    count = {}
    for i in range(16):
        count[i] = 0
    for t in T:
        x = t[0]
        y = t[1]
        for k in range(16):
            v = k^getbits(y,1)
            u = reverse_Sbox(S_Box)[v]
            z = getbits(getbit(x,1),1)^getbit(u,1)
            if z == 0 :
                count[k]+=1
    print(count)
    for i in range(16):
        count[i] = abs(count[i]-num/2)
    print(sorted(count.items(),reverse = True,key=lambda x:x[1])[0])


if __name__ == '__main__':
    x = 0b0010011010110111
    K = 0x99075481e
    Ks = gen_K_list(K)
    for i in range(6):
    	print('密钥%d：%x'%(i,Ks[i]))
    y = encrypt(K,x)
    print('初始明文：', format(x, '016b'))
    print('加密密文：', format(encrypt(K, x), '016b'))
    print('解密结果：', format(decrypt(K, encrypt(K, x)), '016b'))
    assert decrypt(K, encrypt(K, x)) == x
    diff(K)
    # printlinearTable(K)
    # linear(K)
