# 强网杯 2024 复现

接近一年了，拐回来看看，自己发生了什么变化

## 斯内克

贪吃蛇游戏，绑定了虚拟键盘值，但是很混乱

~~~c
__int64 sub_7FF7A0F718C0()
{
  char *v0; // rdi
  __int64 i; // rcx
  _BYTE v3[32]; // [rsp+0h] [rbp-20h] BYREF
  char v4; // [rsp+20h] [rbp+0h] BYREF
  _INPUT_RECORD Buffer; // [rsp+28h] [rbp+8h] BYREF
  DWORD NumberOfEventsRead[11]; // [rsp+54h] [rbp+34h] BYREF
  _BYTE v7[2072]; // [rsp+80h] [rbp+60h] BYREF
  HANDLE hConsoleInput; // [rsp+898h] [rbp+878h]
  int j; // [rsp+8B4h] [rbp+894h]
  int m; // [rsp+8D4h] [rbp+8B4h]
  int k; // [rsp+8F4h] [rbp+8D4h]
  int n; // [rsp+914h] [rbp+8F4h]
  int wVirtualKeyCode; // [rsp+CE4h] [rbp+CC4h]

  v0 = &v4;
  for ( i = 582LL; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  hConsoleInput = GetStdHandle(0xFFFFFFF6);
  if ( PeekConsoleInputW(hConsoleInput, &Buffer, 1u, NumberOfEventsRead) )
  {
    if ( NumberOfEventsRead[0] )
    {
      ReadConsoleInputW(hConsoleInput, &Buffer, 1u, NumberOfEventsRead);
      if ( Buffer.Event.KeyEvent.wVirtualKeyCode != last_move )
      {
        wVirtualKeyCode = Buffer.Event.KeyEvent.wVirtualKeyCode;
        if ( Buffer.Event.KeyEvent.wVirtualKeyCode == 0x25 )// 下
        {
          ++step;
          last_move = 37;
          dword_7FF7A0F7F490 = 3;
          for ( j = 0; j < 1152; ++j )
            *((_BYTE *)lpAddress + j) = ((int)*((unsigned __int8 *)lpAddress + j) >> 5) | (8 * *((_BYTE *)lpAddress + j));
        }
        else
        {
          switch ( wVirtualKeyCode )
          {
            case 0x26:                          // 左
              ++step;
              dword_7FF7A0F7F490 = 0;
              last_move = 38;
              j_memcpy(v7, lpAddress, 0x480uLL);
              for ( k = 0; k < 1152; ++k )
                *((_BYTE *)lpAddress + k) = v7[(k + 6) % 1152];
              break;
            case 0x27:                          // 上
              ++step;
              last_move = 39;
              dword_7FF7A0F7F490 = 2;
              for ( m = 0; m < 1152; ++m )
                *((_BYTE *)lpAddress + m) -= 102;
              break;
            case 0x28:                          // 右
              ++step;
              last_move = 40;
              dword_7FF7A0F7F490 = 1;
              for ( n = 0; n < 1152; ++n )
                *((_BYTE *)lpAddress + n) += 30;
              break;
          }
        }
      }
    }
  }
  return sub_7FF7A0F71384((__int64)v3, (__int64)&unk_7FF7A0F7C1B0);
}
~~~

可以发现每次移动都会修改内存lpAddress的1152字节，此外新的方向键不按下是不会改变方向

交叉引用找到初始化地方

~~~c
__int64 sub_7FF7A0F71C70()
{
  char *v0; // rdi
  __int64 i; // rcx
  _BYTE v3[32]; // [rsp+0h] [rbp-20h] BYREF
  char v4; // [rsp+20h] [rbp+0h] BYREF
  DWORD flOldProtect[59]; // [rsp+24h] [rbp+4h] BYREF

  v0 = &v4;
  for ( i = 10LL; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  lpAddress = VirtualAlloc(0LL, 0x800uLL, 0x3000u, 4u);
  j_memcpy(lpAddress, &unk_7FF7A0F7F000, 1152uLL);
  VirtualProtect(lpAddress, 0x480uLL, 0x40u, flOldProtect);
  Block = malloc(0x18uLL);
  *((_DWORD *)Block + 2) = 2;
  *((_QWORD *)Block + 2) = malloc(8LL * *((int *)Block + 2));
  *(_DWORD *)Block = 10;
  *((_DWORD *)Block + 1) = 10;
  srand(0xDEADBEEF);
  LODWORD(tgt) = rand() % 20;
  HIDWORD(tgt) = rand() % 20;
  return sub_7FF7A0F71384((__int64)v3, (__int64)&unk_7FF7A0F7C240);
}
~~~

提取出来，此外观察到srand初始seed值固定，因此每次生成金币（目标）坐标是相同的

回到main找到check点

~~~c
__int64 sub_7FF7A0F72880()
{
  char *v0; // rdi
  __int64 i; // rcx
  _BYTE v3[32]; // [rsp+0h] [rbp-20h] BYREF
  char v4; // [rsp+20h] [rbp+0h] BYREF
  __int64 v5; // [rsp+848h] [rbp+828h]
  _BYTE Buf2[48]; // [rsp+868h] [rbp+848h] BYREF
  void *v7; // [rsp+898h] [rbp+878h]
  void *v8; // [rsp+8B8h] [rbp+898h]
  void *v10; // [rsp+8F8h] [rbp+8D8h]
  int v11; // [rsp+CC4h] [rbp+CA4h]

  v0 = &v4;
  for ( i = 574LL; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  v5 = *(_QWORD *)Block;
  v11 = dword_7FF7A0F7F490;
  if ( dword_7FF7A0F7F490 )
  {
    switch ( v11 )
    {
      case 1:
        LODWORD(v5) = v5 + 1;
        break;
      case 2:
        --HIDWORD(v5);
        break;
      case 3:
        ++HIDWORD(v5);
        break;
    }
  }
  else
  {
    LODWORD(v5) = v5 - 1;
  }
  if ( (unsigned int)v5 >= 0x14 || HIDWORD(v5) >= 0x14 )
  {
    printf("Game Over!\n");
    printf("In order to survive in the primeval forest, you have to grow in the fastest way possible.\n");
    exit(0);
  }
  if ( v5 == tgt )
  {
    ++dword_7FF7A0F7FA1C;
    ++*((_DWORD *)Block + 2);
    v7 = lpAddress;
    md5((__int64)lpAddress, 1152LL, (__int64)Buf2);	// 找关键特征确认md5
    if ( !j_memcmp(&unk_7FF7A0F7F480, Buf2, 0x10uLL) )
    {
      v8 = lpAddress;
      if ( (unsigned __int8)((__int64 (__fastcall *)(char *))lpAddress)(Str) )
      {
        printf("Game Over!\n");
        exit(1);
      }
    }
    do
    {
      LODWORD(tgt) = rand() % 20;
      HIDWORD(tgt) = rand() % 20;
    }
    while ( tgt == v5 );
  }
  else
  {
    v10 = realloc(*((void **)Block + 2), 8LL * (*((_DWORD *)Block + 2) - 1));
    if ( !v10 )
    {
      printf("Memory allocation failed.\n");
      exit(1);
    }
    *((_QWORD *)Block + 2) = v10;
  }
  *(_QWORD *)Block = v5;
  return sub_7FF7A0F71384((__int64)v3, (__int64)&unk_7FF7A0F7C010);
}
~~~

发现对lpaddress做了md5 check

这道题当时出的不太好，印象里出题人放了提示说是要求贪吃蛇尽可能少的转向，也就是说有一定的算法在里头，比如到达某个点此时方向向右，新的目标点在右上角，那么此时不应该向上而是继续向右，然后再向上

ai模拟了随机数生成，然后我们每到达一个目标就对修改后的数组做一次md5检查

~~~python
from ctypes import c_uint32
from hashlib import md5

class MsvcrtRand:
    """
    A Python class that simulates the C rand() function from the
    Microsoft Visual C++ Runtime (MSVCRT).

    The constants and algorithm are based on the well-known LCG
    used by Microsoft's C standard library.
    """

    def __init__(self, seed=1):
        """
        Initializes the random number generator.
        The default seed is 1, same as the C standard.
        """
        # The internal state of the generator. We use ctypes.c_uint32
        # to ensure the arithmetic wraps around at 2^32, just like in C.
        self.seed = c_uint32(seed)

    def srand(self, seed):
        """
        Equivalent to C's srand(). Sets a new seed.
        """
        self.seed = c_uint32(seed)

    def rand(self):
        """
        Equivalent to C's rand(). Generates the next random number.
        The number is always between 0 and 32767 (RAND_MAX on MSVCRT).
        """
        # 1. Update the internal seed using the LCG formula:
        # next_seed = (current_seed * 214013 + 2531011)
        self.seed.value = self.seed.value * 214013 + 2531011

        # 2. Generate the output value:
        # result = (next_seed / 2^16) & 0x7FFF
        # In bitwise terms, this is a right shift by 16 and then a bitwise AND.
        return (self.seed.value >> 16) & 0x7FFF

def down(v):
    for i in range(len(v)):
        v[i] = ((v[i] >> 5) | (v[i] << 3)) & 0xff
    return v

def up(v):
    for i in range(len(v)):
        v[i] -= 102
        v[i] &= 0xff
    return v

def left(v):
    return v[6:]+v[:6]

def right(v):
    for i in range(len(v)):
        v[i] += 30
        v[i] &= 0xff
    return v

# 创建一个模拟器实例
c_rand_generator = MsvcrtRand()
# 使用 srand() 播种
c_rand_generator.srand(0xDEADBEEF)

lpaddress = [0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0x38, 0x4C, 0xB0, 0x38, 0x6D, 0xEE, 0x3F, 0xC4, 0xB4, 0xB4, 0x09, 0x6A, 0xF0, 0x38, 0x2C, 0x79, 0xF6, 0x34, 0xE9, 0x89, 0x38, 0xAC, 0x7F, 0x35, 0xD4, 0xB4, 0xB4, 0x38, 0x6D, 0x77, 0xF6, 0xB6, 0x38, 0x6D, 0x78, 0xF6, 0xB6, 0x2B, 0x18, 0xB4, 0xB4, 0xB4, 0x3B, 0x81, 0x81, 0x81, 0x81, 0xEF, 0x4E, 0x38, 0x4C, 0x7D, 0xF6, 0x33, 0xD4, 0xB4, 0xB4, 0xB0, 0xE8, 0xF4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB0, 0xE8, 0xF6, 0x2B, 0x27, 0xA3, 0x1D, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0xB0, 0xF8, 0x04, 0x38, 0x89, 0xE3, 0xC3, 0xCA, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0xB0, 0xF8, 0x04, 0x38, 0xB3, 0x67, 0xE3, 0x16, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xD4, 0xB0, 0xF8, 0x04, 0x38, 0xB6, 0xD3, 0xB6, 0xA9, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0xB0, 0xF8, 0x04, 0x38, 0x89, 0xD8, 0xC7, 0x33, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xD4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0xB0, 0xEC, 0xFE, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0x6F, 0x14, 0x4C, 0xEC, 0xFE, 0xB4, 0xB4, 0xB4, 0x2F, 0xC0, 0x2C, 0xEC, 0xFE, 0xB4, 0xB4, 0xB4, 0xCC, 0x6C, 0xFE, 0xB4, 0xB4, 0xB4, 0xB6, 0x24, 0xCC, 0x72, 0xB4, 0xB4, 0xB4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xC4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xC4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x2C, 0xF8, 0x85, 0x37, 0x4C, 0xE8, 0xF6, 0x4C, 0x69, 0xF4, 0xE4, 0x40, 0x4C, 0xD0, 0x2C, 0xE8, 0xF4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xB4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xB4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xD0, 0x62, 0x64, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x2C, 0xF8, 0x85, 0x37, 0x52, 0x54, 0x2F, 0x2F, 0x2F, 0xB0, 0xEC, 0x00, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0x6F, 0x14, 0x4C, 0xEC, 0x00, 0xB4, 0xB4, 0xB4, 0x2F, 0xC0, 0x2C, 0xEC, 0x00, 0xB4, 0xB4, 0xB4, 0xCC, 0x6C, 0x00, 0xB4, 0xB4, 0xB4, 0xB6, 0x24, 0xCC, 0x72, 0xB4, 0xB4, 0xB4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xD4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xE4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xE4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x4C, 0xE8, 0xF6, 0x4C, 0x69, 0xF4, 0xE4, 0x40, 0x4C, 0xD0, 0x2C, 0xE8, 0xF4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xD4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xD4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xD0, 0x62, 0x64, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x2C, 0xF8, 0x85, 0x37, 0x52, 0x54, 0x2F, 0x2F, 0x2F, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0xA0, 0xEC, 0x42, 0xB4, 0xB4, 0xB4, 0x3D, 0xA0, 0xEC, 0x52, 0xB4, 0xB4, 0xB4, 0xBE, 0xA0, 0xEC, 0x62, 0xB4, 0xB4, 0xB4, 0x51, 0xA0, 0xEC, 0x6F, 0xB4, 0xB4, 0xB4, 0x3D, 0xA0, 0xEC, 0x7F, 0xB4, 0xB4, 0xB4, 0x5B, 0xA0, 0xEC, 0x12, 0xB4, 0xB4, 0xB4, 0x8D, 0xA0, 0xEC, 0x22, 0xB4, 0xB4, 0xB4, 0x65, 0xA0, 0xEC, 0x32, 0xB4, 0xB4, 0xB4, 0xA7, 0xA0, 0xEC, 0xBF, 0xB4, 0xB4, 0xB4, 0x4D, 0xA0, 0xEC, 0xCF, 0xB4, 0xB4, 0xB4, 0xAC, 0xA0, 0xEC, 0xDF, 0xB4, 0xB4, 0xB4, 0xF8, 0xA0, 0xEC, 0xEF, 0xB4, 0xB4, 0xB4, 0x06, 0xA0, 0xEC, 0xFF, 0xB4, 0xB4, 0xB4, 0xE9, 0xA0, 0xEC, 0x8F, 0xB4, 0xB4, 0xB4, 0x3B, 0xA0, 0xEC, 0x9F, 0xB4, 0xB4, 0xB4, 0xA3, 0xA0, 0xEC, 0xAF, 0xB4, 0xB4, 0xB4, 0x31, 0xB0, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0x6F, 0x14, 0x4C, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0x2F, 0xC0, 0x2C, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0xCC, 0x6C, 0xF5, 0xC4, 0xB4, 0xB4, 0xB5, 0x68, 0xE6, 0x38, 0xCA, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0x24, 0x1B, 0xF8, 0x04, 0x37, 0x38, 0xCA, 0x6D, 0xF5, 0xC4, 0xB4, 0xB4, 0x24, 0x1B, 0x7D, 0x85, 0x42, 0xB4, 0xB4, 0xB4, 0x63, 0xD0, 0xF7, 0xF4, 0xD3, 0xC0, 0x6F, 0xF4, 0x6F, 0x00, 0xBB, 0xC4, 0x38, 0x4C, 0x3F, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD]
print(len(lpaddress))
start = [10, 10]
tgt = [c_rand_generator.rand()%20, c_rand_generator.rand()%20][::-1]
# 上下左右 -1 1 -2 2
direction = 2
path = ""
while True:
    new_direction = [0, 0]
    row = tgt[0] - start[0]
    col = tgt[1] - start[1]
    print(f"{start}-->{tgt}")
    # print(f"下*{row}" if row > 0 else f"上*{-row}")
    # print(f"右*{col}" if col > 0 else f"左*{-col}")
    if direction == 2:     # 上一次向右
        if row > 0:
            lpaddress = down(lpaddress)
            direction = 1
            path += "S"
        elif row < 0:
            lpaddress = up(lpaddress)
            direction = -1
            path += "W"
        if col < 0:
            lpaddress = left(lpaddress)
            direction = -2
            path += "A"
    elif direction == -2:   # 上一次向左
        if row > 0:
            lpaddress = down(lpaddress)
            direction = 1
            path += "S"
        elif row < 0:
            lpaddress = up(lpaddress)
            direction = -1
            path += "W"
        if col > 0:
            lpaddress = right(lpaddress)
            direction = 2
            path += "D"
    elif direction == 1:   # 上一次向下
        if col > 0:
            lpaddress = right(lpaddress)
            direction = 2
            path += "D"
        elif col < 0:
            lpaddress = left(lpaddress)
            direction = -2
            path += "A"
        if row < 0:
            lpaddress = up(lpaddress)
            direction = -1
            path += "W"
    elif direction == -1:   # 上一次向上
        if col > 0:
            lpaddress = right(lpaddress)
            direction = 2
            path += "D"
        elif col < 0:
            lpaddress = left(lpaddress)
            direction = -2
            path += "A"
        if row > 0:
            lpaddress = down(lpaddress)
            direction = 1
            path += "S"
    print(path)
    if md5(bytes(lpaddress)).hexdigest().upper() == "9C06C08F882D7981E91D663364CE5E2E":
        with open("func", "wb") as f:
            f.write(bytes(lpaddress))
        break
    start = tgt
    while tgt == start:
        tgt = [c_rand_generator.rand()%20, c_rand_generator.rand()%20][::-1]
~~~

最终正确的字节数组写入func，ida检查发现就是个xtea

~~~python
from ctypes import c_uint32

def xtea_decrypt(r, v, key, id):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9E3779B9
    total = c_uint32(delta * r * (id+2)//2)
    for i in range(r):
        v1.value -= (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (total.value + key[(total.value >> 11) & 3])
        total.value -= delta
        v0.value -= (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (total.value + key[total.value & 3])
    return v0.value, v1.value


k = b"W31c0m3. 2 QWBs8"
k = [int.from_bytes(k[i:i+4], byteorder="little") for i in range(0, 16, 4)]
v = [i&0xff for i in [-104, -96, -39, -104, -70, -105, 27, 113, -101, -127, 68, 47, 85, -72, 55, -33]]
v = [int.from_bytes(bytes(v[i:i+4]), byteorder="little") for i in range(0, len(v), 4)]
v[2] ^= v[1]
v[3] ^= v[0]
v[1] ^= v[3]
v[0] ^= v[2]
for i in range(0, len(v), 2):
    v[i:i+2] = xtea_decrypt(32, v[i:i+2], k, i)
v = "".join([int.to_bytes(v[i], byteorder='little', length=4).decode() for i in range(len(v))])
print(v)
~~~

## mips

> Someone has found the mips binary, along with an emulator to execute it. What can you find in them?
>
> USAGE
>
> ./emu ./mips_bin

很明显emu是模拟器，后面是mips编写的代码

~~~c
int __fastcall ftext(int argc, const char **argv, const char **envp)
{
  int *v3; // $v0
  int *v4; // $s0
  _BYTE *v5; // $a0
  int i; // $v1
  char v7; // $a1
  int v8; // $s2
  int v9; // $s0
  int *v11; // $v0
  int *v12; // $v1
  int v13; // $a2
  int v14; // $a1
  int v15; // $a0
  int v16; // $v1
  int v17; // $v0
  int v18; // $v1
  int v19; // $v0
  _DWORD v20[8]; // [sp+20h] [-38h] BYREF
  _DWORD v21[6]; // [sp+40h] [-18h] BYREF

  qmemcpy(v21, "sxrujtv`labiVzbp`vpg|", 21);
  memset(v20, 0, sizeof(v20));
  v3 = (int *)mmap((void *)0x23000, 0x1000u, 7, 2050, -1, 0);
  v4 = 0;
  if ( v3 != (int *)-1 )
    v4 = v3;
  v5 = &opcodes;
  for ( i = 0; i != 96; ++i )
  {
    v7 = i & 3 ^ *v5;
    *v5++ = v7;
  }
  v8 = fork();
  if ( v8 )
  {
    do
    {
      v9 = waitpid(v8, 0, 1);
      sleep(1);
    }
    while ( !v9 );
  }
  else
  {
    v11 = (int *)&opcodes;
    v12 = v4;
    do
    {
      v13 = v11[1];
      v14 = v11[2];
      v15 = v11[3];
      *v12 = *v11;
      v12[1] = v13;
      v12[2] = v14;
      v12[3] = v15;
      v11 += 4;
      v12[3] = v15;
      v12 += 4;
    }
    while ( v11 != &stdio_user_locking );
    v16 = v21[1];
    v4[512] = v21[0];
    v4[513] = v16;
    v17 = v21[2];
    v4[513] = v16;
    v4[514] = v17;
    v18 = v21[3];
    v4[514] = v17;
    v4[515] = v18;
    v19 = v21[4];
    v4[515] = v18;
    v4[516] = v19;
    *((_BYTE *)v4 + 2068) = HIBYTE(v21[5]);
    puts("input your flag, be fast:");
    read(0, v20, 32);
    if ( strlen(v20) != 22 )
      write(1, &unk_40EE5C, 4);
    if ( ((int (__fastcall *)(_DWORD *))v4)(v20) )
      write(1, "wrong\n", 7);
    else
      write(1, "right\n", 7);
  }
  return 0;
}
~~~

直接实现逻辑提取opcode

~~~python
s = [0x00, 0x81, 0x42, 0x26, 0x3C, 0x08, 0x02, 0x01, 0x35, 0x28, 0x3A, 0x03, 0x24, 0x0B, 0x02, 0x16, 0x24, 0x0A, 0x02, 0x03, 0x11, 0x61, 0x02, 0x05, 0x00, 0x01, 0x02, 0x03, 0x21, 0x28, 0x02, 0x02, 0x21, 0x09, 0x02, 0x02, 0x21, 0x4B, 0xFD, 0xFC, 0x11, 0x41, 0x02, 0x09, 0x00, 0x01, 0x02, 0x03, 0x01, 0x8D, 0x62, 0x25, 0x01, 0xAC, 0x6A, 0x25, 0x81, 0x2D, 0x02, 0x03, 0x81, 0x0C, 0x02, 0x03, 0x01, 0x8B, 0x62, 0x25, 0x01, 0xAD, 0x6A, 0x25, 0x11, 0xA1, 0xFD, 0xF7, 0x00, 0x01, 0x02, 0x03, 0x24, 0x0A, 0x02, 0x02, 0x01, 0x61, 0x12, 0x26, 0x03, 0xE1, 0x02, 0x0B, 0x00, 0x01, 0x02, 0x03]
for i in range(96):
    s[i] = i & 3 ^ s[i]

s += [0]*(2068-96)
cmp = b"sxrujtv`labiVzbp`vpg|"
s[512*4:512*4+21] = list(cmp)
with open("func", "wb") as f:
    f.write(bytes(s))
~~~

ida mips大端打开

~~~c
__int64 __fastcall sub_0(char *a1)
{
  __int64 v2; // $a5
  __int64 v3; // $a6
  __int64 v4; // $a7

  v2 = 145408LL;
  v3 = 21LL;
  v4 = 0LL;
  while ( !(*a1 ^ *(char *)v2 ^ (unsigned __int64)v3) )
  {
    v2 = (int)v2 + 1;
    a1 = (char *)((int)a1 + 1);
    v3 = (int)v3 - 1;
    if ( !v3 )
      return v4;
  }
  return 1LL;
}
~~~

实现逻辑

~~~python
cmp = b"sxrujtv`labiVzbp`vpg|"
v = 0x15
for i in range(len(cmp)):
    print(chr(v^cmp[i]), end="")
    v -= 1
~~~

得到`flag{dynamic_reverse}`，很明显假的flag

能分析的地方只有emu了，非常可疑，结合fake flag提示我们打开动态调试，看到底哪里开始出现mips相关东西

调试发现最后一个函数是mips解析器，打印了input your flag等

但是还是没法定位，尝试编译qemu-6.2也失败，没法对比

最终找到方法：搜索0x23000成功定位一处有花指令的地方

![image-20250908222301762](images/image-20250908222301762.png)

去除花指令后得到函数如下

~~~c
__int64 __fastcall sub_7FFFF76FF8E4(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+10h] [rbp-20h]
  int i; // [rsp+14h] [rbp-1Ch]
  int j; // [rsp+18h] [rbp-18h]
  __int64 v5; // [rsp+20h] [rbp-10h]
  __int64 v6; // [rsp+28h] [rbp-8h]

  v5 = *(_QWORD *)(a1 + 528);
  v2 = 0;
  result = *(unsigned int *)(v5 + 128);
  if ( *(_DWORD *)(v5 + 128) == 143360 )
  {
    result = (unsigned int)dword_7FFFF7FF4318;
    if ( dword_7FFFF7FF4318 )
    {
      v6 = sub_7FFFF76FF48E((__int64)&unk_7FFFF7FF5280);
      for ( i = 0; i <= 21; ++i )
        *(_BYTE *)(i + v6) ^= dword_7FFFF7FF4324;
      swap(v6, 7, 11);
      result = swap(v6, 12, 16);
      for ( j = 0; j <= 21; ++j )
      {
        result = cmp[j];
        if ( *(unsigned __int8 *)(j + v6) != (_DWORD)result )
        {
          v2 = 1;
          break;
        }
      }
      if ( !v2 && j == 22 )
        dword_7FFFF7FF431C = 1;
    }
  }
  return result;
}
~~~

交叉引用unk数组发现检查了flag头

![image-20250908222707473](images/image-20250908222707473.png)

开始写rc4解密，由于不知道异或的dword值，所以爆破

~~~python
def KSA(key):
    """ Key-Scheduling Algorithm (KSA) 密钥调度算法"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i%len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def PRGA(S):
    """ Pseudo-Random Generation Algorithm (PRGA) 伪随机数生成算法"""
    i, j = 0, 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K

def rol(v, b):
    return ((v << b) | (v >> (8-b))) & 0xff

def RC4(key, text):
    """ RC4 encryption/decryption """
    S = KSA(key)
    keystream = PRGA(S)
    flag = ""
    for i in range(len(text)):
        char = text[i]
        xor = [0xDE, 0xAD, 0xBE, 0xEF]
        rc4_xor = next(keystream)
        for j in range(32, 127):
            v3 = ((rol(j, 7) << 6) ^ 0xC0 | (rol(j, 7) >> 2) ^ 0x3B) ^ 0xBE
            v3 &= 0xff
            tmp = rc4_xor ^ xor[i&3] ^ rol(rol(rol(v3, 5) ^ 0xAD, 4) ^ 0xDE, 3)
            if tmp == char:
                flag += chr(j)
                break
        if j == 127:
            return
    return flag

for j in range(256):
    cmp = [0x000000C4, 0x000000EE, 0x0000003C, 0x000000BB, 0x000000E7, 0x000000FD, 0x00000067, 0x0000001D, 0x000000F8, 0x00000097, 0x00000068, 0x0000009D, 0x0000000B, 0x0000007F, 0x000000C7, 0x00000080, 0x000000DF, 0x000000F9, 0x0000004B, 0x000000A0, 0x00000046, 0x00000091]
    cmp[12], cmp[16] = cmp[16], cmp[12]
    cmp[7], cmp[11] = cmp[11], cmp[7]
    for i in range(len(cmp)):
        cmp[i] ^= j
    key = b"6105t3"
    flag = RC4(key, cmp)
    if flag:
        print(f"{j}: {RC4(key, cmp)}")
~~~

找到flag

![image-20250908224249306](images/image-20250908224249306.png)

## solve2-apk

java层混淆，不管，直接jeb搜failure字符串，找到如下代码

~~~java
package U0;

import Q.d;
import W.c;
import W0.j;
import androidx.compose.ui.platform.Q0;
import b0.n;
import com.a.myapplication.MainActivity;
import d0.E;
import d0.H;
import d0.K;
import d0.o;
import g1.a;
import h1.h;
import h1.i;
import java.util.Arrays;
import l.p;
import o.l;
import q1.w;
import v.d0;
import w0.k;
import x.T;
import z.g;

public final class f extends i implements a {
    public final int f;
    public final Object g;
    public final Object h;
    public final Object i;

    public f(Object object0, Object object1, Object object2, int v) {
        this.f = v;
        this.g = object0;
        this.h = object1;
        this.i = object2;
        super(0);
    }

    public f(l l0, n n0, a a0) {
        this.f = 3;
        this.g = l0;
        this.h = n0;
        this.i = (i)a0;
        super(0);
    }

    @Override  // g1.a
    public final Object d() {
        Object[] arr_object3;
        H h1;
        H h0;
        boolean z;
        switch(this.f) {
            case 0: {
                goto label_10;
            }
            case 1: {
                ((androidx.compose.ui.platform.a)this.g).removeOnAttachStateChangeListener(((Q0)this.h));
                h.e(((d)this.i), "listener");
                c.B(((androidx.compose.ui.platform.a)this.g)).a.remove(((d)this.i));
                return j.a;
            }
            case 2: {
                goto label_178;
            }
        }

        l l0 = (l)this.g;
        O.d d0 = l.u0(l0, ((n)this.h), ((a)(((i)this.i))));
        if(d0 != null) {
            p p0 = l0.t;
            if(!k.a(p0.A, 0L)) {
                long v = p0.x0(d0, p0.A);
                return d0.f(c.a(-O.c.d(v), -O.c.e(v)));
            }

            throw new IllegalStateException("Expected BringIntoViewRequester to not be used before parents are placed.");
        }

        return null;
    label_10:
        new MainActivity();
        String s = (String)((T)this.h).getValue();
        h.e(s, "s");
        byte[] arr_b = new byte[0];
        int[] arr_v = new int[0];
        int[] arr_v1 = new int[0];
        int v1 = 0;
        int v2 = 0;
        int v3 = 0;
        int v4 = 0;
        int v5 = 0;
        int v6 = 0;
        long v7 = 0x5BE935D0EDBFE83CL;
        int v8 = 24;
        while(Long.compare(v7, 0L) != 0) {
            long v9 = 0x404C98D80D628D27L;
            if(Long.compare(v7, 0x404C98D80D628D27L) == 0) {
                arr_v1[v1] = 0;
                v7 = 0x767AEC22C91BE2BFL;
            }

            long v10 = 8904566903685903062L;
            if(Long.compare(v7, 8904566903685903062L) == 0) {
                v7 = 0x29CB0C5AA5BA5210L;
            }

            long v11 = 0x7F6F5B8E28C072CFL;
            if(Long.compare(v7, 0x7F6F5B8E28C072CFL) == 0) {
                v2 -= 1640531527;
                v7 = 0x1E7D57CBFEE24485L;
            }

            long v12 = 0x123CFD69BDE0364DL;
            if(Long.compare(v7, 0x123CFD69BDE0364DL) == 0) {
                ++v3;
                v7 = 0x3C57CEFFB4FFAFF4L;
            }

            long v13 = 2705319197673083720L;
            if(Long.compare(v7, 2705319197673083720L) == 0) {
                v7 = v8 == 0 ? 0x250D59D18CBA666DL : 0x7032C3F4B5EFAB31L;
            }

            long v14 = 0x41593FC8BF139758L;
            if(Long.compare(v7, 0x41593FC8BF139758L) == 0) {
                v7 = 0x69E4449C056151ACL;
                v8 = 24;
            }

            if(Long.compare(v7, 0x1F45282B0E978C91L) == 0) {
                v7 = 0x380BE8BE1044EE6DL;
            }

            long v15 = 0x2CEBD4941DD371AAL;
            if(Long.compare(v7, 0x29CB0C5AA5BA5210L) == 0) {
                v3 = 0;
                v7 = 0x2CEBD4941DD371AAL;
            }

            if(Long.compare(v7, 0x5260B3C741DB1316L) == 0) {
                v7 = 0x39E2DF14B65FB5B7L;
            }

            if(v7 == 0x380BE8BE1044EE6DL) {
                arr_v1[v1] |= (arr_b[v3] & 0xFF) << v8;
            }
            else {
                v13 = v7;
            }

            if(Long.compare(v13, 0x2CEBD4941DD371AAL) == 0) {
                v13 = v3 >= 8 ? 0x2A7EB92B8AF86758L : 2503205216640455778L;
            }

            long v16 = 0x55CB210B059B852DL;
            long v17 = 0x5335127A3A0A4907L;
            if(Long.compare(v13, 0x55CB210B059B852DL) == 0) {
                v8 += -8;
                v13 = 0x5335127A3A0A4907L;
            }

            long v18 = 2368350050472760653L;
            if(Long.compare(v13, 2368350050472760653L) == 0) {
                v13 = 0x5A88D049059402F6L;
            }

            long v19 = 0x26D3DBBBECB952A4L;
            if(v13 == 0x26D3DBBBECB952A4L) {
                break;
            }

            if(v13 != 0x7032C3F4B5EFAB31L) {
                v16 = v13;
            }

            if(v16 == 0x5335127A3A0A4907L) {
                ++v3;
                v16 = 0x767AEC22C91BE2BFL;
            }

            if(v16 == 0x69E4449C056151ACL) {
                ++v1;
            }
            else {
                v17 = v16;
            }

            long v20 = 0x169A506C8792840DL;
            if(v17 == 0x169A506C8792840DL) {
                v3 += 2;
            }
            else {
                v15 = v17;
            }

            long v21 = 8829928630187910250L;
            if(v15 != 8829928630187910250L) {
                v11 = v15;
            }

            if(Long.compare(v11, 0x1E7D57CBFEE24485L) == 0) {
                v4 = (v5 << 4 ^ v5) + (v2 ^ v5 >>> 5) + v4;
                v11 = 0x50E57F91E168FAC9L;
            }

            long v22 = 8153458827322010710L;
            long v23 = 0x2654EF16F510CF25L;
            if(Long.compare(v11, 8153458827322010710L) == 0) {
                v2 = 0;
                v11 = 0x2654EF16F510CF25L;
            }

            long v24 = 0x2981462384F2153CL;
            if(Long.compare(v11, 0x2981462384F2153CL) == 0) {
                arr_v = new int[]{0x5E5440B0, 2057046228, 0x4A1ED228, 0x233FE7C, 0x96461450, -2002358035, 0xF79BFC89, 0x20C3D75F};
                v11 = 0x62E816E54253B307L;
            }

            if(Long.compare(v11, 0x33C51F874ED9F174L) == 0) {
                v6 = 0x20;
                v11 = 0x4D784B3DF54B096FL;
            }

            if(v11 != 0x767AEC22C91BE2BFL) {
                v10 = v11;
            }
            else if(v3 < 0x20) {
                v10 = 0x1F45282B0E978C91L;
            }

            if(v10 == 0x2A7EB92B8AF86758L) {
                v3 = 0;
                v10 = 0x3C57CEFFB4FFAFF4L;
            }

            if(Long.compare(v10, 0x2654EF16F510CF25L) != 0) {
                v21 = v10;
            }
            else if(v6 > 0) {
                --v6;
            }
            else {
                --v6;
                v21 = 0x1E65F68B123E6E17L;
            }

            if(Long.compare(v21, 0x5BE935D0EDBFE83CL) == 0) {
                v21 = s.length() >= 0x20 ? 0x1E47617FF0CE8BE3L : 0x7C99975CB23FC36BL;
            }

            if(v21 == 0x1E47617FF0CE8BE3L) {
                arr_b = Arrays.copyOf(s.getBytes(), 0x20);
            }
            else {
                v24 = v21;
            }

            if(Long.compare(v24, 0x1E65F68B123E6E17L) == 0) {
                arr_v1[v3] = v4;
                v24 = 0x6F35E9E1070E87BEL;
            }

            if(Long.compare(v24, 0x3C57CEFFB4FFAFF4L) != 0) {
                v18 = v24;
            }
            else if(v3 >= 8) {
                v18 = 0x752D25A60BA93D48L;
            }

            if(v18 == 0x752D25A60BA93D48L) {
                z = H0.a.successWithString(s);
                goto label_171;
            }

            if(v18 != 0x250D59D18CBA666DL) {
                v14 = v18;
            }

            if(v14 == 0x62E816E54253B307L) {
                arr_v1 = new int[8];
            }
            else {
                v9 = v14;
            }

            if(v9 != 0x5A88D049059402F6L) {
                v12 = v9;
            }
            else if(arr_v1[v3] != arr_v[v3]) {
                v12 = 0x5260B3C741DB1316L;
            }

            if(v12 != 0x7C99975CB23FC36BL) {
                v19 = v12;
            }

            if(v19 == 2503205216640455778L) {
                v19 = 0x33C51F874ED9F174L;
            }

            if(v19 == 0x6F35E9E1070E87BEL) {
                arr_v1[v3 + 1] = v5;
            }
            else {
                v20 = v19;
            }

            v7 = 0x491A503216BAC9F4L;
            if(v20 == 0x491A503216BAC9F4L) {
                v5 = arr_v1[v3 + 1];
            }
            else {
                v22 = v20;
            }

            if(v22 == 0x50E57F91E168FAC9L) {
                v5 = (v4 << 4 ^ v4) + (v4 >>> 5 ^ v2) + v5;
            }
            else {
                v23 = v22;
            }

            if(v23 == 0x39E2DF14B65FB5B7L) {
                break;
            }

            if(v23 == 0x4D784B3DF54B096FL) {
                v4 = arr_v1[v3];
            }
            else {
                v7 = v23;
            }
        }

        z = false;
    label_171:
        e e0 = new e(((d0)this.i), (z ? "success" : "failure"), null);
        w.o(((v1.d)this.g), null, 0, e0, 3);
        return j.a;
    label_178:
        E e1 = (E)this.g;
        int v25 = 0;
        e1.A.i = 0;
        g g0 = e1.A.a.p();
        int v26 = g0.g;
        if(v26 > 0) {
            Object[] arr_object = g0.e;
            int v27 = 0;
            do {
            label_186:
                E e2 = ((androidx.compose.ui.node.a)arr_object[v27]).A.o;
                h.b(e2);
                e2.k = e2.l;
                e2.l = 0x7FFFFFFF;
                if(e2.m == 2) {
                    e2.m = 3;
                }

                ++v27;
                if(v27 < v26) {
                    goto label_186;
                }

                goto label_194;
            }
            while(true);
        }
        else {
        label_194:
            h0 = e1.A;
            g g1 = h0.a.p();
            int v28 = g1.g;
            if(v28 > 0) {
                Object[] arr_object1 = g1.e;
                int v29 = 0;
                do {
                label_200:
                    E e3 = ((androidx.compose.ui.node.a)arr_object1[v29]).A.o;
                    h.b(e3);
                    e3.t.d = false;
                    ++v29;
                    if(v29 < v28) {
                        goto label_200;
                    }

                    goto label_205;
                }
                while(true);
            }
            else {
            label_205:
                o o0 = e1.v().L;
                h1 = (H)this.i;
                if(o0 != null) {
                    boolean z1 = o0.k;
                    z.d d1 = (z.d)h1.a.j();
                    int v30 = d1.e.g;
                    for(int v31 = 0; v31 < v30; ++v31) {
                        K k0 = ((androidx.compose.ui.node.a)d1.get(v31)).z.c.u0();
                        if(k0 != null) {
                            k0.k = z1;
                        }
                    }
                }
            }
        }

        ((o)this.h).f0().d();
        if(e1.v().L != null) {
            z.d d2 = (z.d)h1.a.j();
            int v32 = d2.e.g;
            for(int v33 = 0; v33 < v32; ++v33) {
                K k1 = ((androidx.compose.ui.node.a)d2.get(v33)).z.c.u0();
                if(k1 != null) {
                    k1.k = false;
                }
            }
        }

        androidx.compose.ui.node.a a0 = h0.a;
        g g2 = a0.p();
        int v34 = g2.g;
        if(v34 > 0) {
            Object[] arr_object2 = g2.e;
            int v35 = 0;
            do {
            label_235:
                E e4 = ((androidx.compose.ui.node.a)arr_object2[v35]).A.o;
                h.b(e4);
                if(e4.k != e4.l && e4.l == 0x7FFFFFFF) {
                    e4.b0();
                }

                ++v35;
                if(v35 < v34) {
                    goto label_235;
                }

                goto label_241;
            }
            while(true);
        }
        else {
        label_241:
            g g3 = a0.p();
            int v36 = g3.g;
            if(v36 <= 0) {
                return j.a;
            }

            arr_object3 = g3.e;
        }

        do {
            E e5 = ((androidx.compose.ui.node.a)arr_object3[v25]).A.o;
            h.b(e5);
            e5.t.e = e5.t.d;
            ++v25;
        }
        while(v25 < v36);

        return j.a;
    }
}
~~~

可以看到tea类加密特征

一个很大的坑点，jeb反编译不太对，他的key没有反编译出来