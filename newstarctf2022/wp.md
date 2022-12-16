## Web

### Word-For-You

无``WAF``的``SQL``注入:填完留言表后点查询留言，发现``url``的形式是: ``comments.php?name=admin``, 尝试用``sqlmap``直接进行注入：

```sql
sqlmap -u 'url' --dbs #列出数据库名
sqlmap -u 'url' -D dbname --tables #列出表名
sqlmap -u 'url' -D dbname -T tablename --columns #列出表名
sqlmap =u 'url' -D dbname -T tablename -C 'id,name' --dump #列出字段的数据
```

## Reverse
### Pyre
exeinfo查看文件，64位可执执行程序。用IDA打开，在字符串窗口发下如下内容：
![](./wp.assets/2022-12-15-15-24-41.png)
包含许多python的函数，因此这个可执行文件是用python来实现的。逆向的目标是:
$exe \rightarrow pyc \rightarrow py$
- exe可执行文件到pyc文件的转化：一般是通过PyInstaller制作的exe文件的，可以用``pyinstxtractor.py``提取出exe中的资源文件。将脚本文件和exe文件放到同一个目录下，执行如下的命令：
    ```bash
    python pyinstxtractor.py pyre.exe
    ```
则会在当前目录下生成提取后的资源文件。
- pyc文件到py文件的转化：从提取的资源文件中找到与可执行文件同名的pyc文件以及一个struct.pyc文件。用struct.pyc文件补全pyre.pyc文件的头
![](./wp.assets/image.png.png)
补全后的pyre.pyc文件（用struct.pyc的前11个字节覆盖pyre.pyc的前11个字节）
![](./wp.assets/2022-12-15-15-20-31.png)
用uncompyle工具将pyc文件转位py文件
    ```shell
     uncompyle6 pyre.pyc > pyre.py
    ```
得到如下的python源代码文件
```python
# uncompyle6 version 3.8.0
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.10.6 (tags/v3.10.6:9c7b4bd, Aug  1 2022, 21:53:49) [MSC v.1932 64 bit (AMD64)]
# Embedded file name: pyre.py
# Compiled at: 1995-09-28 00:18:56
# Size of source mod 2**32: 272 bytes
flag = ''
encode = 'REla{PSF!!fg}!Y_SN_1_0U'
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]

def enc(input):
    tmp = ''
    for i in range(len(input)):
        tmp += input[table[i]]

    return tmp


if __name__ == '__main__':
    print('Please input your flag:')
    flag = input()
    if len(flag) != 23:
        print('Length Wrong!!')
    else:
        final = enc(flag)
        if final == encode:
            print('Wow,you get the right flag!!')
        else:
            print('Sorry,Your input is Wrong')
# okay decompiling pyre.pyc
```
根据加密函数写解密的脚本：
```python
encode = 'REla{PSF!!fg}!Y_SN_1_0U'
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]
flag=[0]*len(encode)
for i in range(len(encode)):
	flag[table[i]] = encode[i]
print("".join(flag))
```
### EasyRe
给了``easyre.exe``和``enc.dll``两个文件，反汇编二进制文件，分析程序的逻辑：需要输入一个flag,然后调用``enc.dll``中的加密函数对flag进行加密，结果需要等于一个已知的字符串final。那么就用IDA去看dll文件，encode代码如下：
```c
__int64 __fastcall encode_0(const char *a1, __int64 a2)
{
  int v3; // [rsp+24h] [rbp+4h]
  int v4; // [rsp+64h] [rbp+44h]
  int v5; // [rsp+84h] [rbp+64h]

  sub_1800112CB(&unk_180021001);
  v3 = j_strlen(a1);
  v4 = 0;
  v5 = 0;
  while ( v4 < v3 )
  {
    *(_BYTE *)(a2 + v5) = aAbcdefghijklmn[a1[v4] >> 2];
    *(_BYTE *)(a2 + v5 + 1) = aAbcdefghijklmn[((a1[v4 + 1] & 0xF0) >> 4) | (16 * (a1[v4] & 3))];
    *(_BYTE *)(a2 + v5 + 2) = aAbcdefghijklmn[((a1[v4 + 2] & 0xC0) >> 6) | (4 * (a1[v4 + 1] & 0xF))];
    *(_BYTE *)(a2 + v5 + 3) = aAbcdefghijklmn[a1[v4 + 2] & 0x3F];
    v4 += 3;
    v5 += 4;
  }
  if ( v3 % 3 == 1 )
  {
    *(_BYTE *)(a2 + v5 - 1) = 61;
    *(_BYTE *)(a2 + v5 - 2) = 61;
  }
  else if ( v3 % 3 == 2 )
  {
    *(_BYTE *)(a2 + v5 - 1) = 61;
  }
  return sub_18001132A(a2);
}
```
就是一个BASE64加密代码，返回的``sub_18001132A``的代码如下：
```c
const char *__fastcall sub_180011660(const char *a1)
{
  int i; // [rsp+24h] [rbp+4h]

  sub_1800112CB(&unk_180021001);
  for ( i = 0; i < j_strlen(a1); ++i )
    a1[i] ^= Str[i % j_strlen(Str)]; //str="Reverse"
  return a1;
}
```
解密思路就很清晰了：先将final串和Str按字符进行异或，然后将得到的结果base64解密即可。(final需要仔细看一下下标，final首先是将每个值置为0了的)
```python
import base64
final=[8,8,0xE,0xD,0x28,0x40,0x11,0x11,0x3C,0x2E,0x2B,0x1E ,0x3D ,0xF ,0,3 ,0x3B ,0x3D ,0x3C ,0x15 ,0x28,5,0x50,0x46,0x3F,0x2A,0x39,9,0x31,0x56,0x24,
0x1C,0x3F,0x24,0x50,0x3C ,0x2C ,0x25 ,0x23 ,0x4B]
Str = "Reverse"
tmp=[0] * len(final)
for i in range(len(final)):
	tmp[i] = final[i] ^ ord(Str[i % len(Str)])
print(tmp)
enc_flag = bytes(tmp)
print(base64.b64decode(enc_flag.decode()))
```
### 艾克体悟题
安卓逆向题目，首先让程序跑起来。打开模拟器，安装APK
```bash
adb install demo.apk
```
运行程序，提示需要打开另外的Activity:
![](./wp.assets/2022-12-16-10-08-11.png)
用Jadx查看源代码, 需要打开FlagActivity这个活动，然后点击10000次按钮后才能得到flag。
![](./wp.assets/1.png)

一种思路是apk反编译后重新打包，将1w该成1次。步骤如下：
- 下载[apktool](https://ibotpeaches.github.io/Apktool/): 这个工具可以将apk进行反编译和重新打包。执行如下命令：
  ```bash
  java -jar apktool_2.7.0.jar d demo.apk -o new1
  ```
  在生成的文件夹中，修改smali/com/droidlearn/activity_travel/目录下找到FlagActivity$1.smali文件，将其中的0x2710(10000)修改位0x1即可。修改完后用如下命令重新打包：
  ```
  java -jar apktool_2.4.1.jar b new1 -o new2.apk
  ```
  直接安装会报错误，因为没有签名
  ![](./wp.assets/2022-12-16-10-22-30.png)
- 签名操作：利用keytool进行前面，这个工具只要配置了JAVA环境就有。
  ```
  keytool -genkey -alias testalias -keyalg RSA -keysize 2048 -validity 36500 -keystore test.keystore
  ``` 
  需要输入口令和一些答案，最后输入y确定即可。
  生成成功后会在目录下创建test.keystore文件，keytool -list -v -keystore test.keystore查看详细信息，这里的别名(testalias)很重要。然后为apk签名即可：
  ```
  jarsigner -verbose -keystore test.keystore -storepass 123456 -signedjar flag.apk new2.apk testalias
  ```
  -keystore +签名文件，
  -sotrepass +签名口令密码,
  -signedjar后跟三个参数 分别是签名后的apk文件 需要签名的apk文件 签名的别名
  
接着就运行
卸载掉原来安装了的包（com.droidlearn.activity_travel）
```shell
adb devices //查看adb连接的设备
adb shell pm list packages //查看已安装的包名
adb uninstall packageName //卸载
```
安装上重打包的APK
```
adb install flag.apk
```

运行指定的Activity
```
adb shell //进入调试
am start -n 包名/包名.活动名
```
例如我们想要启动FlagActivity这个活动，输入：
```
am start -n com.droidlearn.activity_travel/com.droidlearn.activity_travel.FlagActivity
```
然后自需要点击1次就可以得到flag.
![](./wp.assets/2022-12-16-10-45-27.png)





## Pwn



## Crypto
### ezRabin
查看题目内容：
```python
from Crypto.Util.number import *
from somewhere_you_do_not_know import flag
#flag格式为 flag{XXXX}
def ezprime(n):
    p=getPrime(n)
    while p%4!=3:
        p=getPrime(n)
    return p
p=ezprime(512)
q=ezprime(512)
n=p*q
m=bytes_to_long(flag)
m=(m<<(300))+getRandomNBitInteger(300)
assert m**2>n and m<n
c=pow(m,4,n)
print('c=',c)
print('p=',p)
print('q=',q)
'''
c= 59087040011818617875466940950576089096932769518087477304162753047334728508009365510335057824251636964132317478310267427589970177277870220660958570994888152191522928881774614096675980017700457666192609573774572571582962861504174396725705862549311100229145101667835438230371282904888448863223898642183925834109
p= 10522889477508921233145726452630168129218487981917965097647277937267556441871668611904567713868254050044587941828674788953975031679913879970887998582514571
q= 11287822338267163056031463255265099337492571870189068887689824393221951058498526362126606231275830844407608185240702408947800715624427717739233431252556379
就要花里胡哨（
'''
```
这道题考察的是Rabin加密，和RSA有相似之处，但是也有很大的不同。Rabin中e取固定值e=2,p和q都是模4余3的素数。本题e=4只要依据e=2稍作修改，将4次方看做平方外再套一层平方即可，也就是进行两次e=2时的解密，一共得到4*4=16个解，再右移30位后从中找到flag即可。
```python
import gmpy2
from Crypto.Util.number import *

p=10522889477508921233145726452630168129218487981917965097647277937267556441871668611904567713868254050044587941828674788953975031679913879970887998582514571
q=11287822338267163056031463255265099337492571870189068887689824393221951058498526362126606231275830844407608185240702408947800715624427717739233431252556379
n=p*q
e=2
c=59087040011818617875466940950576089096932769518087477304162753047334728508009365510335057824251636964132317478310267427589970177277870220660958570994888152191522928881774614096675980017700457666192609573774572571582962861504174396725705862549311100229145101667835438230371282904888448863223898642183925834109
inv_p = gmpy2.invert(p, q)
inv_q = gmpy2.invert(q, p)

def de_rabin(c):
    mp = pow(c, (p+1) // 4, p)
    mq = pow(c, (q+1) // 4, q)
    a = (inv_p * p * mq + inv_q * q * mp) % n
    b = n-int(a)
    c = (inv_p * p * mq - inv_q * q * mp) % n
    d = n-int(c)
    return a,b,c,d

'''e=4的解密，就是做两次e=2的rabin解密，
第一次得到4个解，将4个解作为新的c分别再做一次e=2的rabin解密,
所以共得到16个解，右移300位后看看哪个解是flag'''

a,b,c,d=de_rabin(c)
a1,a2,a3,a4=de_rabin(a)
b1,b2,b3,b4=de_rabin(b)
c1,c2,c3,c4=de_rabin(c)
d1,d2,d3,d4=de_rabin(d)

l=[a1,a2,a3,a4,b1,b2,b3,b4,c1,c2,c3,c4,d1,d2,d3,d4]
for ll in l:
    print(long_to_bytes(ll>>300))
```

## Misc



## BlockChain

