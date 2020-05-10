# RSA_Breaking

该仓库存放2016年全国高校密码数学挑战赛的赛题三——RSA加密体制破译的真题及相关解法，并提供RSA密文破解的常规思路。

## 对应攻击方法

![RSA_breaking.png-199.7kB][1]

根据上表，我们在破译明文过程中采用了公共模数攻击法、猜测攻击法、Pollard p-1分解法、低加密指数法、费马分解法和因数碰撞法共六种方法。下面进行说明。

## 解析密文结构

题目给出了21个明文分片的加密结果。针对任意待加密明文，以8字符为单位长度进行划分，得到的结果随后进行相关填充，注意在填充过程中需要加入通信序号，我们可以通过通信序号进行片段还原。具体填充与加密过程可以参考`过程及参数.txt`。根据该txt文档，我们对提供的Frame0-Frame20进行密文解析，分离出重要参数模数n，加密指数e和密文c，脚本如下：

```python
for i in range(21):
    with open("/Users/mac/Desktop/RSA大礼包/frame_set/Frame"+str(i), "r") as f:
        tmp = f.read()
        ns.append(tmp[0:256])
        es.append(tmp[256:512])
        cs.append(tmp[512:768])
```

对解析得到的参数进行分析，分析方法如下：

* 遍历所有的模数N，判断是否存在模数相同的加密片段
* 遍历寻找任意两个模数N的公因子，如果得到不为1的公因子则可以成功分解这两个模数
* 遍历所有加密指数e，寻找低加密指数及对应的加密对
* 剩下的片段采用费马分解和Pollard p-1分解进行尝试
* 常规方法使用完如果还有剩余片段，可以采用猜测攻击的方法。当然，针对猜测攻击的结果需要进行游程计算，以验证结果的精确性。

经过以上分析，得出结论：

* Frame0和Frame4的模数N相同，假设这两片段对应的明文内容相同，则可以使用公共模数攻击的方法
* Frame1和Frame18的模数N具有公共因子，可以通过因数碰撞法还原明文

* Frame3，Frame8，Frame12，Frame16和Frame20采用低加密指数`e=5`进行加密
* Frame7，Frame11，Frame15采用低加密指数`e=3`进行加密

## 公共模数攻击

![Same_modules.PNG-35.2kB][2]

针对Frame0和Frame4，构建共模攻击函数：

```python
# 欧几里得算法
def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

# 公共模数攻击
def same_modulus():
    # 寻找公共模数
    index1 = 0
    index2 = 0
    for i in range(21):
        for j in range(i+1, 21):
            if ns[i] == ns[j]:
                print('Same modulus found!' + str((ns[i], ns[j])))
                index1 ,index2 = i, j  
    e1 = int(es[index1], 16)
    e2 = int(es[index2], 16)
    n = int(ns[index1], 16)
    c1 = int(cs[index1], 16)
    c2 = int(cs[index2], 16)
    s = egcd(e1, e2)
    s1 = s[1]
    s2 = s[2]
    # 求模反元素
    if s1<0:
        s1 = - s1
        c1 = gmpy2.invert(c1, n)
    elif s2<0:
        s2 = - s2
        c2 = gmpy2.invert(c2, n)

    m = pow(c1,s1,n)*pow(c2,s2,n) % n

    print(m)
    print(binascii.a2b_hex(hex(m)[2:]))
    result = binascii.a2b_hex(hex(m)[2:])
    return result
```

得到结果如下：

```python
# Frame0: My secre
# Frame4: My secre
```

## 因数碰撞攻击

针对Frame1和Frame18，构造因数碰撞函数：

```python
# 因数碰撞法
def same_factor():
    plaintext = []
    index = []
    for i in range(21):
        for j in range(i+1, 21):
            if int(ns[i], 16) == int(ns[j], 16):
                continue
            prime = gmpy2.gcd(int(ns[i], 16), int(ns[j], 16))
            if prime != 1:
                print((ns[i], ns[j]))
                print((i, j))
                index.append(i)
                index.append(j)
                p_of_frame = prime
    q_of_frame1 = int(ns[index[0]], 16) // p_of_frame
    q_of_frame18 = int(ns[index[1]], 16) // p_of_frame
    print(p_of_frame)
    print(q_of_frame1, q_of_frame18)

    phi_of_frame1 = (p_of_frame-1)*(q_of_frame1-1)
    phi_of_frame18 = (p_of_frame-1)*(q_of_frame18-1)

    d_of_frame1 = gmpy2.invert(int(es[index[0]],16) ,phi_of_frame1)
    d_of_frame18 = gmpy2.invert(int(es[index[1]], 16), phi_of_frame18)

    plaintext_of_frame1 = gmpy2.powmod(int(cs[index[0]], 16), d_of_frame1, int(ns[index[0]], 16))
    plaintext_of_frame18 = gmpy2.powmod(int(cs[index[1]], 16), d_of_frame18, int(ns[index[1]], 16))

    final_plain_of_frame1 = binascii.a2b_hex(hex(plaintext_of_frame1)[2:])
    final_plain_of_frame18 = binascii.a2b_hex(hex(plaintext_of_frame18)[2:])

    plaintext.append(final_plain_of_frame1)
    plaintext.append(final_plain_of_frame18)

    return plaintext
```

得到结果如下：

```python
# Frame1: . Imagin
# Frame18: m A to B
```

## 低加密指数攻击

![low_e.PNG-23.1kB][3]

通过以上原理可以看出，对于低加密指数进行的攻击实质上为爆破攻击，可以通过循环开方的方法进行破解。构造破解函数如下：

```python
# 低加密指数攻击
# 经过输出检测,发现Frame3,Frame8,Frame12,Frame16,Frame20采用低加密指数e=5进行加密
# 前置函数中国剩余定理
def chinese_remainder_theorem(items):
    N = 1
    for a, n in items:
        N *= n
        result = 0
    for a, n in items:
        m = N//n
        d, r, s = egcd(n, m)
        if d != 1:
            N = N//n
            continue
        result += a*s*m
    return result % N, N
# 低加密指数e == 3
def bruce_e_3():
    bruce_range = [7, 11, 15]
    for i in range(3):
        c = int(cs[bruce_range[i]], 16)
        n = int(ns[bruce_range[i]], 16)
        print("This is frame" + str(i))
        for j in range(20):
            plain = gmpy2.iroot(gmpy2.mpz(c+j*n), 3)
            print("This is test" + str(j))
            print(binascii.a2b_hex(hex(plain[0])[2:]))
def low_e_3():
    sessions=[{"c": int(cs[7], 16) ,"n": int(ns[7], 16)},
    {"c":int(cs[11], 16) ,"n":int(ns[11], 16)},
    {"c":int(cs[15], 16) ,"n":int(ns[15], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开三次方根
    plaintext7_11_15 = gmpy2.iroot(gmpy2.mpz(x), 3)
    return binascii.a2b_hex(hex(plaintext7_11_15[0])[2:])
def low_e_5():
    sessions=[{"c": int(cs[3], 16),"n": int(ns[3], 16)},
    {"c":int(cs[8], 16) ,"n":int(ns[8], 16) },
    {"c":int(cs[12], 16),"n":int(ns[12], 16)},
    {"c":int(cs[16], 16),"n":int(ns[16], 16)},
    {"c":int(cs[20], 16),"n":int(ns[20], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开五次方根
    plaintext3_8_12_16_20 = gmpy2.iroot(gmpy2.mpz(x),5)
    return binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[2:])
```

得到结果如下：

```python
# e = 3对应的三段明文还原失败，均为不可识别的乱码，故需要使用其他方法破解Frame7、Frame11和Frame15
# e = 5
# Frame3: t is a f
# Frame8: t is a f
# Frame12: t is a f
# Frame16: t is a f
# Frame20: t is a f
```

## 费马分解法

![Fermat.PNG-25.1kB][4]

根据原理构建解密函数如下：

```python
# 定义费马分解法,适用于p,q相近的情况
# 爆破之后发现Frame10中的模数可以在短时间内使用此方法分解

def pq(n):
    B=math.factorial(2**14)
    u=0;v=0;i=0
    u0=gmpy2.iroot(n,2)[0]+1
    while(i<=(B-1)):
        u=(u0+i)*(u0+i)-n
        if gmpy2.is_square(u):
            v=gmpy2.isqrt(u)
            break
        i=i+1  
    p=u0+i+v
    return p
def fermat_resolve():
    for i in range(10,14):
        N = int(ns[i], 16)
        p = pq(N)
        print(p)
def get_content_of_frame10():
    p = 9686924917554805418937638872796017160525664579857640590160320300805115443578184985934338583303180178582009591634321755204008394655858254980766008932978699
    n = int(ns[10], 16)
    c = int(cs[10], 16)
    e = int(es[10], 16)
    q = n // p
    phi_of_frame10 = (p-1)*(q-1)
    d = gmpy2.invert(e, phi_of_frame10)
    m = gmpy2.powmod(c, d, n)
    final_plain = binascii.a2b_hex(hex(m)[2:])
    return final_plain
```

爆破运行之后发现Frame10可以被快速解密，结果如下：

```python
# Frame10: will get
```

## Pollard p-1分解法

![Pollardp-1.png-64.9kB][5]

根据以上原理，构造Pollard p-1分解函数：

```python
# 定义Pollard p-1分解法,适用于p-1或q-1能够被小素数整除的情况
# 经过爆破发现Frame2,Frame6,Frame19的模数可以使用该方法分解
def pp1(n):
    B=2**20
    a=2
    for i in range(2,B+1):
        a=pow(a,i,n)
        d=gmpy2.gcd(a-1,n)
        if (d>=2)and(d<=(n-1)):
            q=n//d
            n=q*d
    return d
def pollard_resolve():
    index_list = [2,6,19]
    plaintext = []
    for i in range(3):
        N = int(ns[index_list[i]], 16)
        c = int(cs[index_list[i]], 16)
        e = int(es[index_list[i]], 16)
        p = pp1(N)
        print("p of "+ str(index_list[i]) + " is : " + str(p))
        q = N // p
        phi_of_frame = (p-1)*(q-1)
        d = gmpy2.invert(e, phi_of_frame)
        m = gmpy2.powmod(c, d, N)
        plaintext.append(binascii.a2b_hex(hex(m)[2:]))
    return plaintext
```

使用该函数对所有内容进行爆破处理，发现Frame2，Frame6和Frame19的模数可以使用该方法分解，于是处理后结果如下：

```python
# Frame2: That is
# Frame6: "Logic "
# Frame19: instein.
```

至此已完成使用常规RSA破解方法对题目的分析，结合所有的明文片段，我们得到现有明文：

```
Frame0 My secre
Frame1 . Imagin
Frame2  That is 
Frame3 t is a f
Frame4 My secre
Frame5 
Frame6  "Logic 
Frame7 
Frame8 t is a f
Frame9
Frame10 will get
Frame11
Frame12 t is a f
Frame13
Frame14
Frame15
Frame16 t is a f
Frame17
Frame18 m A to B
Frame19 instein.
Frame20 t is a f
```

## 猜测攻击

结合上述破译结果及通信序号，我们整理之后发现可以连缀成有语义的句子，但部分区域存在空缺。于是使用Google搜索等方法找到原句。填补空缺之后进行相关游程计算。

由于该项目重点在于理清RSA破译思路，故剩余工作不进行赘述。

## 明文结果

经过以上破译工作，明文结果如下：

```python
"My secret is a famous saying of Albert Einstein. That is \"Logic will get you from A to B. Imagination will take you everywhere.\""
```


  [1]: http://static.zybuluo.com/B1ank/rtbsvh6g89kyyxvzar3x13ir/RSA_breaking.png
  [2]: http://static.zybuluo.com/B1ank/sqduwfektaos1ycflb95t6r9/Same_modules.PNG
  [3]: http://static.zybuluo.com/B1ank/mg5oc4wlaawvfi9yqdpjqtoa/low_e.PNG
  [4]: http://static.zybuluo.com/B1ank/okm3wmq253mjvepasm2nw9bn/Fermat.PNG
  [5]: http://static.zybuluo.com/B1ank/l7mr898qyw22hkmez2aiu1c1/Pollardp-1.png