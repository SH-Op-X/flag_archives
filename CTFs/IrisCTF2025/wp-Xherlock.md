# IrisCTF 2025复现

## Now this will run on my 486?

利用sigaction实现SMC，unk_555555556218是字节码，sub_5555555552C8是一个类VM（handler）用来处理不同指令，本质上实现了个JIT（即时编译）

~~~c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // ebx
  unsigned int v4; // eax
  struct sigaction v6; // [rsp+0h] [rbp-438h] BYREF
  _BYTE src[904]; // [rsp+A0h] [rbp-398h] BYREF
  unsigned __int64 v8; // [rsp+428h] [rbp-10h]

  v8 = __readfsqword(0x28u);
  v6.sa_flags = 4;
  v6.sa_handler = (__sighandler_t)sub_5555555552C8;
  sigaction(4, &v6, 0LL);
  qmemcpy(src, &unk_555555556218, 0x379uLL);
  len = 889LL;
  addr = mmap(0LL, 0x379uLL, 3, 34, -1, 0LL);
  v3 = 1;
  if ( addr != (void *)-1LL )
  {
    qword_555555558020 = mmap(0LL, qword_555555558010, 3, 34, -1, 0LL);
    if ( qword_555555558020 != (void *)-1LL )
    {
      memcpy(addr, src, len);
      if ( mprotect(addr, len, 5) == -1 )
      {
        return 1;
      }
      else if ( mprotect(qword_555555558020, qword_555555558010, 3) == -1 )
      {
        return 1;
      }
      else
      {
        v4 = ((__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD, void *))addr)(
               0LL,
               0LL,
               0LL,
               0LL,
               qword_555555558020);
        v3 = v4;
        if ( v4 )
          __printf_chk(1LL, "Program returned \"incorrect\" (%d).\n", v4);
        else
          puts("Program returned \"correct\"!");
        munmap(addr, len);
        munmap(qword_555555558020, qword_555555558010);
      }
    }
  }
  return v3;
}
~~~

~~~c
__int64 __fastcall sub_5555555552C8(__int64 a1, __int64 a2, __int64 a3)
{
  char *v3; // rbp
  unsigned __int8 v4; // bl
  int v5; // ebx
  int v7; // edx
  int v8; // eax
  char v9; // al
  char v10; // dl
  char v11; // al
  char v12; // dl
  int v13; // eax
  char v14; // al
  char v15; // dl

  v3 = *(char **)(a3 + 168);
  v4 = *v3;
  ((void (__fastcall *)(__int64, __int64))sub_555555555260)(a1, a2);
  if ( v4 > 0x62u )
  {
    if ( v4 <= 0xEAu )
    {
      if ( v4 <= 0xC3u )
      {
        if ( v4 == 0x82 )
        {
          v8 = (_DWORD)addr + 8 * *(_DWORD *)(v3 + 3) - ((_DWORD)v3 + 5);
          *v3 = 0xE9;
          *(_DWORD *)(v3 + 1) = v8;
          v3[5] = 0x90;
          *((_WORD *)v3 + 3) = 0x9090;
        }
        else if ( v4 == 0x9A )
        {
          v5 = (_DWORD)addr + 8 * *(_DWORD *)(v3 + 3) - ((_DWORD)v3 + 8);
          *v3 = -123;
          v3[1] = sub_555555555249(v3[1], v3[1]);
          *((_WORD *)v3 + 1) = 0x840F;
          *((_DWORD *)v3 + 1) = v5;
        }
      }
      else
      {
        switch ( v4 )
        {
          case 0xC4:
            v9 = v3[1];
            v10 = v3[2];
            *v3 = 0x42;
            v3[1] = 0x8B;
            v3[2] = (8 * v9) & 0x38 | 4;
            v3[3] = v10 & 7;
            *((_DWORD *)v3 + 1) = 0x90909090;
            break;
          case 0xC5:
            v11 = v3[1];
            v12 = v3[2];
            *v3 = 0x42;
            v3[1] = 0x89;
            v3[2] = (8 * v11) & 0x38 | 4;
            v3[3] = v12 & 7;
            *((_DWORD *)v3 + 1) = 0x90909090;
            break;
          case 0xD4:
            v13 = (_DWORD)addr + 8 * *(_DWORD *)(v3 + 3) - ((_DWORD)v3 + 5);
            *v3 = 0xE8;
            *(_DWORD *)(v3 + 1) = v13;
            v3[5] = 0x90;
            *((_WORD *)v3 + 3) = 0x9090;
            break;
          case 0xD5:
            *(_DWORD *)v3 = 0x909090C3;
            *((_DWORD *)v3 + 1) = 0x90909090;
            break;
          case 0xD6:
            v14 = v3[1];
            v15 = v3[2];
            *(_WORD *)v3 = 0x8D4A;
            v3[2] = (8 * v14) & 0x38 | 4;
            v3[3] = v15 & 7;
            *((_DWORD *)v3 + 1) = 0x90909090;
            break;
          case 0xEA:
            *(_DWORD *)v3 = 0x9090050F;
            *((_DWORD *)v3 + 1) = 0x90909090;
            break;
          default:
            return ((__int64 (*)(void))sub_555555555294)();
        }
      }
    }
  }
  else if ( v4 > 5u )
  {
    switch ( v4 )
    {
      case 6u:
        *v3 = 1;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0x90909090;
        *((_WORD *)v3 + 3) = 0x9090;
        break;
      case 7u:
        *v3 = 0x29;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0x90909090;
        *((_WORD *)v3 + 3) = 0x9090;
        break;
      case 0xEu:
        *v3 = 0x31;
        v3[1] = sub_555555555249(v3[1], v3[1]);
        *(_DWORD *)(v3 + 2) = 0x90909090;
        *((_WORD *)v3 + 3) = 0x9090;
        break;
      case 0x16u:
        *v3 = 0x89;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0x90909090;
        *((_WORD *)v3 + 3) = 0x9090;
        break;
      case 0x17u:
        v7 = *(_DWORD *)(v3 + 3);
        *v3 = v3[1] & 7 | 0xB8;
        *(_DWORD *)(v3 + 1) = v7;
        v3[5] = 0x90;
        *((_WORD *)v3 + 3) = 0x9090;
        break;
      case 0x1Eu:
        *v3 = 0x39;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0xFC0950F;
        *((_WORD *)v3 + 3) = 0xC0B6;
        break;
      case 0x1Fu:
        *v3 = 0x39;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0xFC0940F;
        *((_WORD *)v3 + 3) = 0xC0B6;
        break;
      case 0x27u:
        *v3 = 0x39;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0xFC09C0F;
        *((_WORD *)v3 + 3) = 0xC0B6;
        break;
      case 0x2Fu:
        *v3 = 0x39;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0xFC09E0F;
        *((_WORD *)v3 + 3) = 0xC0B6;
        break;
      case 0x37u:
        *v3 = 0x39;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0xFC09F0F;
        *((_WORD *)v3 + 3) = 0xC0B6;
        break;
      case 0x3Fu:
        *v3 = 0x39;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0xFC09D0F;
        *((_WORD *)v3 + 3) = 0xC0B6;
        break;
      case 0x60u:
        *v3 = 0x21;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0x90909090;
        *((_WORD *)v3 + 3) = 0x9090;
        break;
      case 0x61u:
        *v3 = 9;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0x90909090;
        *((_WORD *)v3 + 3) = -28528;
        break;
      case 0x62u:
        *v3 = 0x31;
        v3[1] = sub_555555555249(v3[2], v3[1]);
        *(_DWORD *)(v3 + 2) = 0x90909090;
        *((_WORD *)v3 + 3) = 0x9090;
        break;
      default:
        return ((__int64 (*)(void))sub_555555555294)();
    }
  }
  return ((__int64 (*)(void))sub_555555555294)();
}
~~~

可以通过动态调试发现，输入32位字符，检查总和是否等于0xcff，然后每4字节做一个异或比较

首先输入`iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiH`保证满足总和，然后每四字节比较完有个跳转手动修改下zf标志位，获取所有异或值和比较值，异或回去即可得到flag

~~~python
xor = [0xBF51B0D7, 0x75CC547B, 0x4F0FD83A, 0xA2117744, 0xECD0CEC6, 0x2E19F9FA, 0x32EA83D9, 0xE5EB61E0]
cmp = [0xCC38C2BE, 0x0EAA2018, 0x1078B74D, 0xDB631232, 0x98A0A199, 0x42789493, 0x5685E086, 0x98CA4085]
print(b"".join([(xor[i]^cmp[i]).to_bytes(length=4, byteorder="little") for i in range(8)]))
~~~

`irisctf{wow_very_optimal_code!!}`

官方给出源码了，perfect

https://github.com/IrisSec/IrisCTF-2025-Challenges/blob/main/nowthiswillrunonmy486/src/mainiris.c

## Crispy Kelp

小小的加密罢了，需要注意是utf8编码，加密公式如下
$$
Result1[i] = key\_part + (random\_key[i]\oplus flag[i])\\
Result2[i] = key\_part + (random\_key[i]\oplus Result1[i])
$$
拿到Result1、Result2、key\_part即可解密

~~~python
kelpfile_content = "ebb398ebb58cebb594ebb389ebb3a4ebb4b1ebb693ebb2b4ebb58febb38debb5a3ebb59cebb3a2ebb682ebb68eebb39debb485ebb3b3ebb488ebb480ebb2acebb580ebb39febb58debb59cebb5b5ebb4abebb3a4ebb6a2ebb5bfebb69aebb48cebb5b2ebb486ebb3b7ebb5b6ebb4b1ebb58febb6a4ebb587ebb48aebb583ebb382ebb59aebb385ebb395ebb384ebb2acebb2a6f097a4a9f097a8bef097a8b9f097a4bff097a59ff097a9b4f097a6bef097a5a7f097a8b3f097a5bff097a998f097a980f097a4a7f097a895f097a6bbf097a59bf097a894f097a687f097a6a8f097a88ff097a584f097a99cf097a4b8f097a8a8f097a8b9f097aa8bf097aa82f097a68ff097a794f097a9b0f097a880f097a6aff097a8b3f097a6b1f097a4bbf097a9aef097a8b3f097a99ff097a7a2f097a9bcf097a782f097a8a7f097a5a3f097a8acf097a691f097a4b0f097a695f097a5bd"
utf8_bytes = bytes.fromhex(kelpfile_content)
utf8_string = utf8_bytes.decode('utf-8')
final_runes = list(map(ord, utf8_string))
total_len = len(final_runes)
L = (total_len - 1) // 2
key_part = final_runes[L]
Result2 = final_runes[L + 1:]
Result1 = final_runes[:L]
random_key = [(Result2[i]-key_part)^Result1[i] for i in range(L)]
flag = [(Result1[i]-key_part)^random_key[i] for i in range(L)]
print(bytes(flag).decode())
~~~

`irisctf{k3lp_1s_4_h34lthy_r3pl4c3m3n7_f0r_ch1p5}`

## bunny jumper!

js混淆很厉害，观察可以发现通过C值来做控制流改变，可以把js在浏览器开发者源面板打开可以拿到格式化好的代码，然后直接写到js，写个check("aaaaa")开始调试，发现中间很复杂，可以直接在r的调用上写console.log打印调用下标

1. 读取了52、45、37、10下标指向的字符，拼接起来（这里可以把flag写长点了）
2. 通过判断长度（`26645 == (C = -24747 * (b >= a.length) + 26645`）遍历拼接字符，实现计数功能`t[a[b]] = (t[a[b]] || 0) + 1`，结果在t字典中
3. 把结果通过map传给c（`c = Object.entries(t).map...`）然后sort
4. 开始从c里取值（s），然后push进A，然后再传给G
5. ...开始调不明白了

因此尝试trace，在`C = `前一行加一行`console.log(xxx)`，然后再去把一些条件判断处打印出来，还可以适当在一些关键位置打印出来变量值

由此拿到trace记录，交给gpt5可以复现出一套正确的加密（我不会算法呜呜）

~~~python
from collections import Counter
import heapq
import base64

# ========== 1) 规范哈夫曼：从字符串 s 计算码长表 w ==========
def canonical_huffman_code_lengths(s):
    """
    返回 w: {codepoint(int) -> codelen(int)}
    单符号特判：长度记为 1。
    """
    freq = Counter(s)
    if not freq:
        return {}
    if len(freq) == 1:
        # 只有一个符号，长度给 1（常见特判）
        (cp, _), = ((ord(ch), c) for ch, c in freq.items())
        return {cp: 1}

    # 用最小堆构造哈夫曼树，得到每个符号的深度=码长
    # 堆元素: (权重, 自增id, 节点)；叶子节点: ('leaf', codepoint)；内部节点: ('node', left, right)
    uid = 0
    heap = []
    for ch, f in freq.items():
        heap.append((f, uid, ('leaf', ord(ch))))
        uid += 1
    heapq.heapify(heap)

    while len(heap) > 1:
        f1, _, n1 = heapq.heappop(heap)
        f2, _, n2 = heapq.heappop(heap)
        heapq.heappush(heap, (f1 + f2, uid, ('node', n1, n2)))
        uid += 1

    _, _, root = heap[0]
    # DFS 统计每个叶子的深度
    w = {}
    def dfs(node, depth):
        kind = node[0]
        if kind == 'leaf':
            _, cp = node
            w[cp] = depth
        else:
            _, l, r = node
            dfs(l, depth + 1)
            dfs(r, depth + 1)
    dfs(root, 0)

    # 规范哈夫曼的“规范性”只影响码字，不影响码长；这里我们只需要长度
    return w

# ========== 2) 把 w 序列化为位流并按字节打包 ==========
def serialize_w_to_bytes(w):
    """
    顺序 m=0..255：
      - 若 w[m] <= 0：输出 1 个比特 0
      - 否则：输出 1 个比特 1 + 再输出 4 个比特表示 w[m]
        这 4 位按 **低位在先（LSB-first）** 的顺序写入位流
    然后按 8 位打包为字节（高位在前，e=(e<<1)|bit），末尾不足 8 位左移补 0。
    """
    out = bytearray()
    e = 0  # 当前字节缓冲
    n = 0  # 当前字节已写入的位数 [0..8)

    def put_bit(bit: int):
        nonlocal e, n
        e = ((e << 1) | (bit & 1)) & 0xFF  # 高位在前推入
        n += 1
        if n == 8:
            out.append(e)
            e = 0
            n = 0

    for m in range(256):
        L = int(w.get(m, 0))
        if L <= 0:
            put_bit(0)
        else:
            put_bit(1)
            # 写 4 比特表示码长，**低位在先（LSB-first）**
            for k in range(4):
                put_bit((L >> k) & 1)

    # 收尾：还有残余位则左移补齐后输出
    if n > 0:
        e = (e << (8 - n)) & 0xFF
        out.append(e)

    return bytes(out)

# ========== 3) 与 "jump" 循环异或 + Base64 ==========
JUMP_KEY = b'jump'  # 0x6a, 0x75, 0x6d, 0x70

def xor_with_jump(b):
    return bytes(b[i] ^ JUMP_KEY[i % 4] for i in range(len(b)))

def middle_base64_from_w(w):
    B = serialize_w_to_bytes(w)   # 打包前原始字节序列
    O = xor_with_jump(B)          # 与 "jump" 异或后的字节序列
    return base64.b64encode(O).decode()

# ========== 4) 便捷入口：从 4 字符直接得到 middle ==========
def middle_from_four_chars(s4):
    assert len(s4) == 4
    w = canonical_huffman_code_lengths(s4)
    return middle_base64_from_w(w)

# ========== 5) 小测试：'aaaa' ==========
if __name__ == "__main__":
    s4 = "aaad"
    w = canonical_huffman_code_lengths(s4)
    print("w =", {k: w[k] for k in sorted(w)})

    B = serialize_w_to_bytes(w)
    O = xor_with_jump(B)

    print("B (packed, before XOR):", B.hex(" "))
    print("K (jump stream)       :", (JUMP_KEY * ((len(O)+3)//4))[:len(O)].hex(" "))
    print("O (after XOR)         :", O.hex(" "))
    print("Base64(middle)        :", base64.b64encode(O).decode())

    # 反验证：O ^ K = B
    K = (JUMP_KEY * ((len(O)+3)//4))[:len(O)]
    B2 = bytes(o ^ k for o, k in zip(O, K))
    assert B2 == B

~~~

好了gpt5秒了

~~~python
from base64 import b64decode as b64d
import z3

# ======= 输入：按 [middle_b64, group_number, middle_b64, group_number, ...] 交错 =======
x = [
'dW1wanVrcGp', 151986214, 'dW1wanZtcGp', 168894767, 'dW1wahVtcGp', 143414, 'dW1wanVtEGp', 202515241, 'dW1x6nVtcGp', 219753011, 'dW1wcn89cGp', 268849, 'dW1xKnVucSp', 18095146, 'dW1xKhU9cGp', 35464242, 'dW1wOnVsMAp', 51128620, 'dW1wQnBtaGp', 51782960, 'dW1x6zVv8Gp', 68360487, 'dW1wCnVt1Wp', 85665324, 'dW1waXVv+mp', 84281399, 'dW1xL3ZtcGp', 102047534, 'dW1wfnVtEG9', 253767992, 'dW1x6nVFcH5', 118959923, 'dW1wanfucH5', 119284279, 'dW1xKPZtcGp', 135141663, 'dW1xKiVtdmp', 152903206, 'dW1xKtVtdmp', 153103667, 'dW1xKn9ucGp', 168895531, 'dW1xL3VucGp', 185603370, 'dW1x6PVtWGp', 236723758, 'dW1wCnVFcG9', 286799160, 'dW1xLHXNcGp', 387656501, 'dW1xKnVFWH5', 320086583, 'dW1xKnVFcS9', 303307048, 'dW1wQtXNWGp', 170208564
]

# ======= 比较时用到的常量：i = btoa("jumpjumpj")，基线 middle = "dW1wanVtcGp" =======
pref = b'anVtcGp1bXBq'           # = btoa("jumpjumpj")
base = pref + b'dW1wanVtcGp='     # 作为比对“基线”的 i + baseline_middle
jump_key = b'jump'                # XOR 密钥

def get_diff_bits_vs_base(target_middle_b64: bytes):
    """
    还原“i + target_middle”与“i + baseline_middle”的逐比特差异位置。
    返回：[(bit_idx_global, byte_idx, bit_in_byte), ...]，已按顺序排好。
    """
    wanted = pref + target_middle_b64 + b'='
    wanted = b64d(wanted)    # i + target_middle
    cur    = b64d(base)      # i + baseline_middle

    parts = []
    for i in range(min(len(wanted), len(cur))):
        if wanted[i] != cur[i]:
            a = wanted[i]; b = cur[i]
            # 高位在前（与代码里 e=(e<<1)|bit 的打包一致）
            for j in range(8):
                if ((a >> (7-j)) & 1) != ((b >> (7-j)) & 1):
                    parts.append((i*8 + j, i, j))
    return parts

def group_number_to_indices(n: int):
    """
    32 位组数拆 4 个下标（按你前面的用法：高字节到低字节再整体 reverse）
    """
    idxs = [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
    return idxs[::-1]

def infer_freq_from_parts(parts):
    """
    核心经验规则：差异位两两成对；每对在一个“4 位槽”中。
    a:pair首位的全局bit下标；offset 每次 +4；字符 = chr(a - offset)
    若 b - a == 1 → 该字符频次 2；否则 → 频次 1。
    若整组只有一个字符 → 频次 4（"aaaa" 情形）。
    返回：freq: {char -> count}
    """
    pairs = [(parts[i][0], parts[i+1][0]) for i in range(0, len(parts), 2)]
    freq = {}
    offset = 0
    for a, b in pairs:
        c = chr(a - offset)
        freq[c] = 2 if (b - a == 1) else 1
        offset += 4
    if len(freq) == 1:
        # 单字符特判：出现 4 次
        k = next(iter(freq))
        freq[k] = 4
    return freq

# ======= 把所有组的频次约束丢给 Z3 =======
def solve_flag_from_groups(x_pairs, length_hint=57, alphabet=None, prefix=b"irisctf{", suffix=b"}"):
    """
    x_pairs: 交错数组 [middle_b64:str/bytes, group_number:int, ...]
    length_hint: flag 长度（可按最大索引+1自动推断）
    alphabet: 允许字符集（默认用 CTF 常见集合）
    prefix/suffix: 可选已知前后缀
    """
    # 规范化输入 & 推断 flag 长度
    pairs = []
    max_idx = -1
    for i in range(len(x_pairs)-2, -1, -2):  # 按你之前使用的“逆序”处理
        mid = x_pairs[i]
        if isinstance(mid, str):
            mid = mid.encode()
        n   = int(x_pairs[i+1])
        idxs = group_number_to_indices(n)
        max_idx = max(max_idx, *idxs)
        parts = get_diff_bits_vs_base(mid)
        freq  = infer_freq_from_parts(parts)
        pairs.append((idxs, freq))
    L = max(length_hint, max_idx+1)

    # 变量
    flag = [z3.BitVec(f"flag_{i}", 8) for i in range(L)]
    s = z3.Solver()

    # 字母表（默认：大小写、数字、下划线与大括号）
    if alphabet is None:
        def _in_ranges(v, a, b): return z3.And(v >= ord(a), v <= ord(b))
        allowed = z3.Or(
            _in_ranges(flag[0], 'a', 'z'))  # dummy, will rebuild below
        allowed_clauses = []
        for v in flag:
            allowed_clauses.append(z3.Or(
                _in_ranges(v,'a','z'),
                _in_ranges(v,'A','Z'),
                _in_ranges(v,'0','9'),
                v == ord('_'),
                v == ord('{'),
                v == ord('}')
            ))
        s.add(*allowed_clauses)
    else:
        allowed_set = set(alphabet)
        for v in flag:
            s.add(z3.Or(*[v == ord(ch) for ch in allowed_set]))

    # 已知前后缀（按需要加/改）
    if prefix:
        for i,ch in enumerate(prefix):
            if i < L:
                s.add(flag[i] == ch)
    if suffix and (L >= 1):
        s.add(flag[L-1] == suffix[0])

    # 每一组频次约束
    for gid, (idxs, freq) in enumerate(pairs):
        # 该组可能出现的字符集合
        keys = sorted(freq.keys())
        # 1) 每个候选字符的“恰好出现 freq[c] 次”
        for c in keys:
            eqs = [flag[i] == ord(c) for i in idxs]
            s.add(z3.PbEq([(e,1) for e in eqs], freq[c]))
        # 2) 组内 4 个位置必须都属于 keys
        for i in idxs:
            s.add(z3.Or(*[flag[i] == ord(c) for c in keys]))
        # 3) 组内恰好 4 个位置被键集覆盖（冗余校验，可省）
        all_eqs = [z3.Or(*[flag[i] == ord(c) for c in keys]) for i in idxs]
        s.add(z3.PbEq([(e,1) for e in all_eqs], 4))

    assert s.check() == z3.sat, "UNSAT：检查组数据/位模式/字节序是否正确"
    m = s.model()
    out = bytes(int(m[v].as_long()) for v in flag)
    return out

# ========== 运行示例 ==========
if __name__ == "__main__":
    flag = solve_flag_from_groups(x, length_hint=57)
    print(flag.decode(errors="replace"))

~~~

## rev-lifetime

稍微看了下出题人solve，果断放弃，貌似类似llvm编译得