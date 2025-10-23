# 京麒CTF挑战赛第三届 复现

## drillbeam

java层没东西，直接看native层找到了控制流平坦化的几处函数，用IDA d810就可以恢复

~~~c

__int64 __fastcall sub_3550(__int64 result, __int64 a2)
{
  __int64 v2; // x5
  char v3; // w3
  unsigned int v4; // w4
  int i; // [xsp+8h] [xbp-18h]

  if ( dword_6518 != 1 )
  {
    for ( i = 0; ; ++i )
    {
      v2 = i;
      v3 = *(_BYTE *)(a2 + 20 + i);
      v4 = i % 20u;
      if ( i == 6 )
        break;
      *(_BYTE *)(result + v2) = v3 ^ *(_BYTE *)(a2 + v4);
    }
    *(_BYTE *)(result + i) = v3 ^ *(_BYTE *)(a2 + v4);
    dword_6518 = 1;
  }
  return result;
}
void *__fastcall sub_184C(const void *a1, size_t n, __int128 *a3, _QWORD *a4)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v31 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v30 = *a3;
  v20 = 0LL;
  if ( !(_BYTE)v30 )
    goto LABEL_3;
  if ( !BYTE1(v30) )
  {
    v20 = 1LL;
    goto LABEL_3;
  }
  if ( !BYTE2(v30) )
  {
    v20 = 2LL;
    goto LABEL_3;
  }
  if ( !BYTE3(v30) )
  {
    v20 = 3LL;
    goto LABEL_3;
  }
  if ( !BYTE4(v30) )
  {
    v20 = 4LL;
    goto LABEL_3;
  }
  if ( !BYTE5(v30) )
  {
    v20 = 5LL;
    goto LABEL_3;
  }
  if ( !BYTE6(v30) )
  {
    v20 = 6LL;
    goto LABEL_3;
  }
  if ( !BYTE7(v30) )
  {
    v20 = 7LL;
    goto LABEL_3;
  }
  if ( !BYTE8(v30) )
  {
    v20 = 8LL;
    goto LABEL_3;
  }
  if ( !BYTE9(v30) )
  {
    v20 = 9LL;
    goto LABEL_3;
  }
  if ( !BYTE10(v30) )
  {
    v20 = 10LL;
    goto LABEL_3;
  }
  if ( !BYTE11(v30) )
  {
    v20 = 11LL;
    goto LABEL_3;
  }
  if ( !BYTE12(v30) )
  {
    v20 = 12LL;
    goto LABEL_3;
  }
  if ( !BYTE13(v30) )
  {
    v20 = 13LL;
    goto LABEL_3;
  }
  if ( !BYTE14(v30) )
  {
    v20 = 14LL;
LABEL_3:
    memset((char *)&v30 + v20 + 1, 0, v20 ^ 0xF);
  }
  v12 = 0LL;
  if ( n )
  {
    v7 = n >> 2;
    if ( (n & 3) != 0 )
      ++v7;
    v21 = v7;
    nmemb = v7 + 1;
    v23 = (int *)calloc(v7 + 1, 4uLL);
    v12 = 0LL;
    if ( v23 )
    {
      v23[v21] = n;
      memcpy(v23, a1, n);
      v24 = calloc(4uLL, 4uLL);
      if ( v24 )
      {
        *v24 = v30;
        v25 = &v23[(unsigned int)(nmemb - 1)];
        if ( (_DWORD)nmemb != 1 )
        {
          v26 = qword_64F0;
          v18 = (unsigned int)*v25;
          for ( i = 0x34 / (unsigned int)nmemb + 5; ; --i )
          {
            v27 = HIDWORD(v18) + v26;
            v28 = ((unsigned int)(HIDWORD(v18) + v26) >> 2) & 3;
            v16 = 0LL;
            v15 = v18;
            v17 = *v23;
            while ( 1 )
            {
              v8 = v23[v16 + 1];
              v29 = ((((4 * v8) ^ (v15 >> 5)) + ((v8 >> 3) ^ (16 * v15))) ^ ((*((_DWORD *)v24 + (v16 & 3 ^ v28)) ^ v15)
                                                                           + (v8 ^ v27)))
                  + v17;
              v23[v16] = v29;
              if ( v16 + 1 == (_DWORD)nmemb - 1 )
                break;
              v17 = v8;
              ++v16;
              v15 = v29;
            }
            v5 = ((((4 * *v23) ^ (v29 >> 5)) + (((unsigned int)*v23 >> 3) ^ (16 * v29))) ^ ((*((_DWORD *)v24
                                                                                             + (v28 ^ ((_BYTE)nmemb - 1) & 3)) ^ v29)
                                                                                          + (*v23 ^ v27)))
               + *v25;
            *v25 = v5;
            if ( !i )
              break;
            LODWORD(v18) = v5;
            HIDWORD(v18) += v26;
          }
        }
        v6 = malloc((4 * nmemb) | 1);
        memcpy(v6, v23, 4 * nmemb);
        *((_BYTE *)v6 + 4 * nmemb) = 0;
        *a4 = 4 * nmemb;
        free(v23);
        v13 = v6;
        v14 = (int *)v24;
      }
      else
      {
        v13 = 0LL;
        v14 = v23;
      }
      free(v14);
      return v13;
    }
  }
  return (void *)v12;
}void __fastcall sub_2F5C(JNIEnv *a1, __int64 a2, __int64 a3)
{
  int v5; // w0
  size_t v6; // x21
  const void *v8; // [xsp+40h] [xbp-30h]
  _QWORD v9[2]; // [xsp+60h] [xbp-10h] BYREF

  v9[1] = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v5 = ((__int64 (__fastcall *)(JNIEnv *, __int64))(*a1)->GetStringUTFLength)(a1, a3);
  v6 = v5;
  v9[0] = v5;
  v8 = (const void *)((__int64 (__fastcall *)(JNIEnv *, __int64, _QWORD))(*a1)->GetStringUTFChars)(a1, a3, 0LL);
  sub_3550((__int64)&unk_6510, (__int64)&unk_13BF);
  sub_184C(v8, v6, (__int128 *)&unk_6510, v9);
  malloc((2LL * v9[0]) | 1);
  __asm { BR              X9 }
}
__int64 __fastcall sub_3550(__int64 result, __int64 a2)
{
  __int64 v2; // x5
  char v3; // w3
  unsigned int v4; // w4
  int i; // [xsp+8h] [xbp-18h]

  if ( dword_6518 != 1 )
  {
    for ( i = 0; ; ++i )
    {
      v2 = i;
      v3 = *(_BYTE *)(a2 + 20 + i);
      v4 = i % 20u;
      if ( i == 6 )
        break;
      *(_BYTE *)(result + v2) = v3 ^ *(_BYTE *)(a2 + v4);
    }
    *(_BYTE *)(result + i) = v3 ^ *(_BYTE *)(a2 + v4);
    dword_6518 = 1;
  }
  return result;
}
void *__fastcall sub_184C(const void *a1, size_t n, __int128 *a3, _QWORD *a4)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v31 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v30 = *a3;
  v20 = 0LL;
  if ( !(_BYTE)v30 )
    goto LABEL_3;
  if ( !BYTE1(v30) )
  {
    v20 = 1LL;
    goto LABEL_3;
  }
  if ( !BYTE2(v30) )
  {
    v20 = 2LL;
    goto LABEL_3;
  }
  if ( !BYTE3(v30) )
  {
    v20 = 3LL;
    goto LABEL_3;
  }
  if ( !BYTE4(v30) )
  {
    v20 = 4LL;
    goto LABEL_3;
  }
  if ( !BYTE5(v30) )
  {
    v20 = 5LL;
    goto LABEL_3;
  }
  if ( !BYTE6(v30) )
  {
    v20 = 6LL;
    goto LABEL_3;
  }
  if ( !BYTE7(v30) )
  {
    v20 = 7LL;
    goto LABEL_3;
  }
  if ( !BYTE8(v30) )
  {
    v20 = 8LL;
    goto LABEL_3;
  }
  if ( !BYTE9(v30) )
  {
    v20 = 9LL;
    goto LABEL_3;
  }
  if ( !BYTE10(v30) )
  {
    v20 = 10LL;
    goto LABEL_3;
  }
  if ( !BYTE11(v30) )
  {
    v20 = 11LL;
    goto LABEL_3;
  }
  if ( !BYTE12(v30) )
  {
    v20 = 12LL;
    goto LABEL_3;
  }
  if ( !BYTE13(v30) )
  {
    v20 = 13LL;
    goto LABEL_3;
  }
  if ( !BYTE14(v30) )
  {
    v20 = 14LL;
LABEL_3:
    memset((char *)&v30 + v20 + 1, 0, v20 ^ 0xF);
  }
  v12 = 0LL;
  if ( n )
  {
    v7 = n >> 2;
    if ( (n & 3) != 0 )
      ++v7;
    v21 = v7;
    nmemb = v7 + 1;
    v23 = (int *)calloc(v7 + 1, 4uLL);
    v12 = 0LL;
    if ( v23 )
    {
      v23[v21] = n;
      memcpy(v23, a1, n);
      v24 = calloc(4uLL, 4uLL);
      if ( v24 )
      {
        *v24 = v30;
        v25 = &v23[(unsigned int)(nmemb - 1)];
        if ( (_DWORD)nmemb != 1 )
        {
          v26 = qword_64F0;
          v18 = (unsigned int)*v25;
          for ( i = 0x34 / (unsigned int)nmemb + 5; ; --i )
          {
            v27 = HIDWORD(v18) + v26;
            v28 = ((unsigned int)(HIDWORD(v18) + v26) >> 2) & 3;
            v16 = 0LL;
            v15 = v18;
            v17 = *v23;
            while ( 1 )
            {
              v8 = v23[v16 + 1];
              v29 = ((((4 * v8) ^ (v15 >> 5)) + ((v8 >> 3) ^ (16 * v15))) ^ ((*((_DWORD *)v24 + (v16 & 3 ^ v28)) ^ v15)
                                                                           + (v8 ^ v27)))
                  + v17;
              v23[v16] = v29;
              if ( v16 + 1 == (_DWORD)nmemb - 1 )
                break;
              v17 = v8;
              ++v16;
              v15 = v29;
            }
            v5 = ((((4 * *v23) ^ (v29 >> 5)) + (((unsigned int)*v23 >> 3) ^ (16 * v29))) ^ ((*((_DWORD *)v24
                                                                                             + (v28 ^ ((_BYTE)nmemb - 1) & 3)) ^ v29)
                                                                                          + (*v23 ^ v27)))
               + *v25;
            *v25 = v5;
            if ( !i )
              break;
            LODWORD(v18) = v5;
            HIDWORD(v18) += v26;
          }
        }
        v6 = malloc((4 * nmemb) | 1);
        memcpy(v6, v23, 4 * nmemb);
        *((_BYTE *)v6 + 4 * nmemb) = 0;
        *a4 = 4 * nmemb;
        free(v23);
        v13 = v6;
        v14 = (int *)v24;
      }
      else
      {
        v13 = 0LL;
        v14 = v23;
      }
      free(v14);
      return v13;
    }
  }
  return (void *)v12;
}
~~~

很明显，先是解密得到密钥，然后xxtea加密，尝试解密xxtea发现报错，怀疑delta值有问题

直接尝试hook发现值是0x7c1ca759

~~~js
Java.perform(function() {
    const moduleName = Process.findModuleByName("libre0.so");
    const functionOffset = 0x1B5C; // 函数的偏移地址

    const baseAddr = moduleName.base;
    console.log("libre0.so的基地址是: " + baseAddr);

    // 3. 计算函数的绝对地址
    const functionAddr = baseAddr.add(functionOffset);
    console.log("要Hook的函数绝对地址是: " + functionAddr);

    // 4. 使用 Interceptor.attach 来拦截
    Interceptor.attach(functionAddr, {
        // 当代码执行到 hookAddr 时，onEnter 会被调用
        // 此时，0x1B58 处的指令已经执行完毕
        onEnter: function(args) {
            console.log("\n[+] 成功 Hook 到地址: " + functionAddr);
            const x10_value = this.context.x10;
            console.log("指令 0x1B58 (LDR X10, ...) 执行完毕后, X10 的值是: " + x10_value);
        }
    });
});
~~~

去尝试同构加密发现对的上（16字节后面还有个额外的字节，所以加密完是20字节），但是去解密就不对了，不知道什么原因，八成是反hook了，哭死，但是看不懂啊

看wp说是得爆破delta值了，让ai写了个，注意只需要检查前16字符是否为hex字符即可

~~~c
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h> // For sysconf
#include <ctype.h>  // For isprint

// --- XXTEA 解密核心函数 ---
void xxtea_decrypt(uint32_t* v, uint32_t n, const uint32_t* key, uint32_t delta) {
    uint32_t r = 6 + 52 / n;
    uint32_t total = delta * r;
    uint32_t v0, v1, e;
    v1 = v[0];
    for (unsigned int i = 0; i < r; ++i) {
        e = (total >> 2) & 3;
        // 从 v[n-1] 到 v[1]
        for (uint32_t j = n - 1; j > 0; --j) {
            v0 = v[j - 1];
            v[j] -= (((v0 >> 5) ^ (v1 << 2)) + ((v1 >> 3) ^ (v0 << 4))) ^ ((total ^ v1) + (key[(j & 3) ^ e] ^ v0));
            v1 = v[j];
        }
        // 处理 v[0]
        v0 = v[n - 1];
        v[0] -= (((v0 >> 5) ^ (v1 << 2)) + ((v1 >> 3) ^ (v0 << 4))) ^ ((total ^ v1) + (key[(0 & 3) ^ e] ^ v0));
        v1 = v[0];
        
        total -= delta;
    }
}

// --- 多线程相关 ---

// 传递给每个线程的参数
typedef struct {
    int thread_id;
    uint64_t start_delta;
    uint64_t end_delta;
    const uint32_t* v_data;
    const uint32_t* k_data;
    uint32_t n;
} thread_args_t;

// 全局共享状态
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile bool found_flag = false;
uint32_t final_delta = 0;
char final_plaintext[128] = {0};

// 线程工作函数
void* worker(void* args) {
    thread_args_t* t_args = (thread_args_t*)args;
    uint32_t v_copy[t_args->n]; // 创建密文的本地副本，因为解密是原地操作

    printf("\[Thread-%d\] 开始搜索 Delta... 范围: 0x%llx -> 0x%llx\n",
           t_args->thread_id, t_args->start_delta, t_args->end_delta);

    for (uint64_t delta = t_args->start_delta; delta < t_args->end_delta; ++delta) {
        // 检查是否应该停止
        pthread_mutex_lock(&result_mutex);
        if (found_flag) {
            pthread_mutex_unlock(&result_mutex);
            printf("[Thread-%d] 收到停止信号, 退出。\n", t_args->thread_id);
            return NULL;
        }
        pthread_mutex_unlock(&result_mutex);

        // 每次解密前都必须重置为原始密文
        memcpy(v_copy, t_args->v_data, t_args->n * sizeof(uint32_t));

        xxtea_decrypt(v_copy, t_args->n, t_args->k_data, (uint32_t)delta);
        bool is_hex_string = true;
        // 检查整个解密后的字符串是否可打印
        for (uint32_t i = 0; i < 16; ++i) {
            char c = ((char*)v_copy)[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                is_hex_string = false;
                break;
            }
        }
        if (is_hex_string) {
            pthread_mutex_lock(&result_mutex);
            if (!found_flag) { // 双重检查，防止多个线程同时发现
                found_flag = true;
                final_delta = (uint32_t)delta;
                // 拷贝结果，去除可能的尾部空字节
                strncpy(final_plaintext, (const char*)v_copy, sizeof(final_plaintext) - 1);
                
                printf("\n============================================================\n");
                printf("🎉 [Thread-%d] 成功找到正确的 Delta!\n", t_args->thread_id);
                printf("  - Delta (hex): 0x%x\n", final_delta);
                printf("  - Delta (dec): %u\n", final_delta);
                printf("  - 解密明文: %s\n", final_plaintext);
                printf("============================================================\n");
            }
            pthread_mutex_unlock(&result_mutex);
            return NULL; // 找到后退出线程
        }
        
        // 打印进度
        if (delta % 4000000 == 0 && delta != t_args->start_delta) {
            printf("[Thread-%d] ...仍在搜索, 当前 Delta: 0x%llx\n", t_args->thread_id, delta);
        }
    }

    printf("[Thread-%d] 已完成其搜索范围。\n", t_args->thread_id);
    return NULL;
}


int main() {
    // --- 已知数据 ---
    const uint32_t k_data[] = { 0x35343131, 0x00003431, 0x00000000, 0x00000000};
    const uint32_t v_data[] = { 0xd4e81e8c, 0x6b1d212e, 0x9c0b9e64, 0x36c8bd33, 0x92791fc};
    const uint32_t n = sizeof(v_data) / sizeof(v_data[0]);

    // --- 多线程设置 ---
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    int num_threads = num_cores;
    printf("检测到 %ld 个CPU核心, 将启动 %d 个线程进行爆破。\n", num_cores, num_threads);

    const uint64_t search_space = 0x100000000; // 2^32
    uint64_t chunk_size = search_space / num_threads;

    pthread_t threads[num_threads];
    thread_args_t thread_args[num_threads];

    printf("\n开始爆破...\n");
    double start_time = (double)clock() / CLOCKS_PER_SEC;

    for (int i = 0; i < num_threads; ++i) {
        thread_args[i].thread_id = i + 1;
        thread_args[i].start_delta = i * chunk_size;
        thread_args[i].end_delta = (i == num_threads - 1) ? search_space : (i + 1) * chunk_size;
        thread_args[i].v_data = v_data;
        thread_args[i].k_data = k_data;
        thread_args[i].n = n;
        
        pthread_create(&threads[i], NULL, worker, &thread_args[i]);
    }

    // 等待所有线程完成
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }
    
    double end_time = (double)clock() / CLOCKS_PER_SEC;

    if (found_flag) {
        printf("\n爆破完成！总耗时: %.2f 秒。\n", end_time - start_time);
    } else {
        printf("\n搜索了整个空间, 未找到有效的 Delta。总耗时: %.2f 秒。\n", end_time - start_time);
    }

    return 0;
}
~~~

得到flag为ae14fb329be518bc

~~~
============================================================
🎉 [Thread-10] 成功找到正确的 Delta!
  - Delta (hex): 0x7c1ca806
  - Delta (dec): 2082252806
  - 解密明文: ae14fb329be518bc
============================================================
~~~

## Risk

还是native层，真机sdk有点老没法安装了

~~~c
__int64 __fastcall Java_com_example_risk_MainActivity_stringFromJNI(
        JNIEnv *a1,
        int a2,
        __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        __int64 a7,
        __int64 a8,
        int a9,
        char a10,
        int a11,
        void *a12,
        char a13,
        int a14,
        void *a15)
{
  JNIEnv v17; // x9
  _BYTE *v18; // x0
  int v19; // w9
  _BYTE *v20; // x20
  __int64 v21; // x8
  void (__fastcall *v22)(_BYTE *, char *); // x22
  unsigned int (__fastcall *v23)(char *, void *); // x23
  char *v24; // x21
  void *v25; // x24
  __int64 result; // x0
  __int64 v27; // x19
  char v28[16]; // [xsp+8h] [xbp-A028h] BYREF
  void *v29; // [xsp+18h] [xbp-A018h]
  char v30[16]; // [xsp+20h] [xbp-A010h] BYREF
  void *v31; // [xsp+30h] [xbp-A000h]
  __int64 v32; // [xsp+A028h] [xbp-8h]

  v32 = *(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v17 = *a1;
  strcpy(v28, "\nWrong");
  v18 = (v17->GetStringUTFChars)(a1, a3, 0LL, a4, a5, a6, a7, a8);
  v19 = *v18;
  v20 = v18;
  if ( *v18 )
  {
    v21 = 1LL;
    while ( (v19 - 58) > 0xFFFFFFF5 )
    {
      v19 = v18[v21++];
      if ( !v19 )
        goto LABEL_5;
    }
    ((*a1)->ReleaseStringUTFChars)(a1, a3, v18);
    return ((*a1)->NewStringUTF)(a1, "Wrong");
  }
  else
  {
LABEL_5:
    v30[0] = 20;
    strcpy(&v30[1], "__lI11lli1");
    v22 = sub_E3B0(&xmmword_217E8, v30);
    if ( (v30[0] & 1) != 0 )
      operator delete(v31);
    strcpy(v30, "\nentry");
    v23 = sub_E3B0(&xmmword_217E8, v30);
    if ( (v30[0] & 1) != 0 )
      operator delete(v31);
    v24 = &v28[1];
    if ( v23 )
    {
      v25 = malloc(0x300uLL);
      v22(v20, v30);
      if ( !v23(v30, v25) )
        std::string::assign(v28, "Right");
      if ( (v28[0] & 1) != 0 )
        v24 = v29;
    }
    result = ((*a1)->NewStringUTF)(a1, v24);
    if ( (v28[0] & 1) != 0 )
    {
      v27 = result;
      operator delete(v29);
      return v27;
    }
  }
  return result;
}
~~~

很明显`__lI11lli1`和`entry`都是asset文件里的，猜测是动态加载了函数字节，进sub_E3B0不断找最终找到真实逻辑

~~~c
__int64 __usercall sub_E4B4@<X0>(__int64 a1@<X0>, __int64 a2@<X8>)
{
  JNIEnv *v4; // x20
  __int64 v5; // x0
  __int64 v6; // x21
  __int64 v7; // x0
  JNIEnv v8; // x8
  __int64 v9; // x23
  __int64 v10; // x0
  __int64 v11; // x22
  __int64 v12; // x23
  unsigned int v13; // w25
  __int64 v14; // x26
  char *v15; // x24
  __int64 v16; // x9
  int8x16_t v18; // q0
  __int64 v19; // x10
  int8x16_t v20; // q1
  int8x16_t v21; // q2
  int8x16_t *v22; // x11
  __int64 v23; // x10
  void *v24[4]; // [xsp+0h] [xbp-20h] BYREF

  v24[3] = *(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v24[0] = 0LL;
  if ( qword_21810 )
  {
    ((*qword_21810)->FindClass)(qword_21810, v24, 65542LL);
    v4 = v24[0];
    if ( v24[0] || (((*qword_21810)->GetVersion)(qword_21810, v24, 0LL), (v4 = v24[0]) != 0LL) )
    {
      v5 = ((*v4)->FindClass)(v4, "com/example/risk/MainActivity");
      if ( v5 )
      {
        v6 = v5;
        v7 = ((*v4)->GetStaticMethodID)(v4, v5, "readAssetFile", "(Ljava/lang/String;)[B");
        v8 = *v4;
        if ( v7 )
        {
          v9 = v7;
          v10 = (v8->NewStringUTF)(v4, a1);
          if ( v10 )
          {
            v11 = v10;
            v12 = sub_F108(v4, v6, v9, v10);
            sub_CB30(a2);
            if ( !v12 )
            {
LABEL_31:
              ((*v4)->DeleteLocalRef)(v4, v11);
              return ((*v4)->DeleteLocalRef)(v4, v6);
            }
            v13 = ((*v4)->GetArrayLength)(v4, v12);
            v14 = ((*v4)->GetByteArrayElements)(v4, v12, 0LL);
            if ( !v14 )
            {
LABEL_30:
              ((*v4)->DeleteLocalRef)(v4, v12);
              goto LABEL_31;
            }
            memset(v24, 0, 24);
            if ( !v13 )
            {
              v15 = 0LL;
LABEL_28:
              sub_16B14(a2, v15, v13);
              ((*v4)->ReleaseByteArrayElements)(v4, v12, v14, 2LL);
              if ( v15 )
                operator delete(v15);
              goto LABEL_30;
            }
            if ( (v13 & 0x80000000) != 0 )
              sub_FF60(v24);
            v15 = operator new(v13);
            memset(v15, 0, v13);
            v16 = 0LL;
            if ( v13 >= 8 && &v15[-v14] >= 0x20 )
            {
              if ( v13 < 0x20 )
              {
                v16 = 0LL;
                goto LABEL_24;
              }
              v18.n128_u64[0] = 0xE9E9E9E9E9E9E9E9LL;
              v18.n128_u64[1] = 0xE9E9E9E9E9E9E9E9LL;
              v19 = 0LL;
              v16 = v13 & 0x7FFFFFE0;
              do
              {
                v20 = *(v14 + v19);
                v21 = *(v14 + v19 + 16);
                v22 = &v15[v19];
                v19 += 32LL;
                *v22 = veorq_s8(v20, v18);
                v22[1] = veorq_s8(v21, v18);
              }
              while ( v16 != v19 );
              if ( v16 == v13 )
                goto LABEL_28;
              if ( (v13 & 0x18) != 0 )
              {
LABEL_24:
                v23 = v16;
                v16 = v13 & 0x7FFFFFF8;
                do
                {
                  *&v15[v23] = veor_s8(*(v14 + v23), 0xE9E9E9E9E9E9E9E9LL);
                  v23 += 8LL;
                }
                while ( v16 != v23 );
                if ( v16 == v13 )
                  goto LABEL_28;
                goto LABEL_27;
              }
            }
            do
            {
LABEL_27:
              v15[v16] = *(v14 + v16) ^ 0xE9;
              ++v16;
            }
            while ( v13 != v16 );
            goto LABEL_28;
          }
          v8 = *v4;
        }
        (v8->DeleteLocalRef)(v4, v6);
      }
    }
  }
  return sub_CB30(a2);
}
~~~

对传入的文件名进行asset查找读取，然后异或了0xE9，直接cyberchef异或E9导出得到两个函数的arm字节码再去反编译

好了，没法arm64反编译，真是怪的很，已root了的真机sdk低又跑不起来，明明很简单但是被卡住了，待我会学校刷个vivo老机器试试

## Customize Virtual Machine

~~~c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // ebp
  unsigned __int64 v4; // r14
  void *v5; // rbp
  char *v6; // rbx
  __int64 v7; // rax
  int v8; // ecx
  unsigned __int64 v9; // rcx
  unsigned __int64 v10; // rcx
  unsigned int v11; // eax
  unsigned int v12; // ebp
  char v13; // bl
  int v14; // ecx
  __int64 v15; // rcx
  __int64 v16; // rcx
  const char *v17; // rdi
  bool v19; // [rsp+3h] [rbp-B5h]
  unsigned int v20; // [rsp+4h] [rbp-B4h]
  __int64 v21; // [rsp+8h] [rbp-B0h]
  _OWORD s1[3]; // [rsp+10h] [rbp-A8h] BYREF
  __int16 v23; // [rsp+40h] [rbp-78h]
  char s[104]; // [rsp+50h] [rbp-68h] BYREF

  v3 = 0;
  printf("input:");
  __isoc99_scanf("%50s", s);
  if ( strlen(s) != 0x32 )
  {
    puts("Wrong. Try Again.");
    return v3;
  }
  v21 = -sysconf(30);
  v4 = 0LL;
  v19 = 1;
  v20 = 0;
  while ( 1 )
  {
    v5 = (void *)(v21 & (unsigned __int64)*(&off_555555559080 + v4));
    v6 = (char *)(dword_555555559210[v4] + *(&off_555555559080 + v4) - (_UNKNOWN *)v5);
    if ( mprotect(v5, (size_t)v6, 7) == -1 )
      break;
    v7 = (__int64)*(&off_555555559080 + v4);
    v8 = dword_555555559210[v4];
    if ( v4 >= 0xF )
    {
      if ( v8 != 1 )
      {
        v10 = 0LL;
        do
          *(_BYTE *)(v7 + v10++) ^= s[v4];
        while ( v10 < dword_555555559210[v4] - 1LL );
      }
    }
    else if ( v8 )
    {
      v9 = 0LL;
      do
        *(_BYTE *)(v7 + v9++) ^= s[v4];
      while ( v9 < dword_555555559210[v4] );
    }
    mprotect(v5, (size_t)v6, 5);
    v19 = v4++ < 0x31;
    if ( v4 == 50 )
      goto LABEL_15;
  }
  perror("mprotect failed");
  v20 = 1;
LABEL_15:
  if ( v19 )
    return v20;
  memset(s1, 0, sizeof(s1));
  v23 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  do
  {
    v15 = dword_5555555592E0[v12];
    if ( v15 == 0x33 )
    {
      v16 = v13++;
      *((_BYTE *)s1 + v16) = v11;
      goto LABEL_18;
    }
    if ( (_DWORD)v15 != 0x32 )
    {
      v11 = ((__int64 (__fastcall *)(_QWORD))*(&off_555555559080 + v15))(v11);
LABEL_18:
      v14 = 1;
      goto LABEL_19;
    }
    v11 = dword_5555555592E0[v12 + 1];
    v14 = 2;
LABEL_19:
    v12 += v14;
  }
  while ( v12 < 0x1AA );
  if ( bcmp(s1, "Congratulations! Your flag is flag{your_input}!^_^", 0x32uLL) )
    v17 = "Wrong. Try Again.";
  else
    v17 = (const char *)s1;
  puts(v17);
  return v20;
}
~~~

核心难点在于off_555555559080里的多组SMC，最开始做法是pin，感觉其实是可行的，但是不稳定而且非常慢，所以只用来帮我爆破了几个先被检查位置了的字符（得到`c9zabahaaaaaaaaqjaaaauaaaaaaLaaaaaaaaabaaaablMaaa5`）

~~~python
import os
import collections
import time
from pwn import *
import concurrent.futures

# --- 全局配置 ---
# 这些是整个脚本共享的常量，放在顶层是合适的

PIN_COMMAND = ["./pin -t inscount0_cout.so -- ../customVM"]
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!"
DUMMY_CHAR = "a"
# 设置并发线程数
MAX_WORKERS = 10 

# 你提供的原始攻击顺序
attack_order_raw = [0, 16, 16, 49, 15, 38, 1, 2, 21, 44, 15, 45, 3, 43, 21, 29, 43, 6, 16, 28, 4, 29, 28, 1, 34, 5, 14, 3, 12, 29, 4, 46, 31, 6, 36, 39, 2, 7, 48, 29, 10, 2, 36, 8, 39, 20, 46, 9, 3, 34, 48, 0, 25, 21, 10, 11, 4, 11, 10, 49, 8, 12, 37, 47, 23, 0, 30, 13, 5, 46, 9, 49, 30, 14, 38, 31, 15, 7, 33, 24, 15, 5, 1, 27, 16, 27, 13, 16, 17, 26, 30, 2, 0, 16, 12, 18, 17, 49, 24, 47, 7, 19, 39, 8, 15, 45, 4, 20, 10, 36, 3, 27, 20, 3, 21, 44, 26, 18, 43, 41, 21, 22, 15, 37, 38, 35, 48, 24, 41, 23, 39, 31, 41, 24, 14, 4, 18, 6, 25, 11, 41, 26, 31, 43, 49, 9, 40, 27, 7, 31, 42, 16, 3, 17, 28, 2, 7, 43, 15, 29, 2, 43, 10, 30, 6, 33, 19, 0, 5, 11, 31, 8, 45, 29, 0, 32, 44, 25, 11, 47, 16, 40, 33, 22, 15, 13, 46, 35, 24, 34, 6, 1, 17, 21, 12, 41, 37, 1, 35, 46, 36, 9, 12, 34, 44, 48, 39, 37, 1, 9, 25, 18, 5, 26, 33, 38, 10, 31, 28, 48, 39, 42, 36, 15, 40, 34, 36, 31, 44, 12, 11, 42, 22, 41, 9, 22, 12, 42, 5, 14, 41, 24, 23, 43, 48, 30, 44, 22, 16, 39, 2, 23, 45, 2, 40, 1, 20, 4, 32, 46, 17, 47, 44, 45, 47, 33, 26, 48, 31, 4, 46, 24, 18, 44, 49, 18]


# --- 多线程工作函数 ---
def test_single_char(pos, char, base_flag_list):
    """
    测试单个字符在指定位置的指令数。
    这是每个线程要执行的工作单元。
    """
    context.log_level = 'error'
    temp_flag_list = list(base_flag_list)
    temp_flag_list[pos] = char
    test_flag = "".join(temp_flag_list)

    try:
        p = process(PIN_COMMAND, shell=True)
        p.sendline(test_flag.encode())
        output = p.recvall(timeout=10)
        p.close()

        lines = output.strip().splitlines()
        if lines:
            instruction_count = int(lines[-1].decode().split(' ')[-1])
            return (char, instruction_count)
        else:
            return (char, -1)
    except (EOFError, PwnlibException, ValueError):
        return (char, -1)


# --- 主逻辑函数 ---
def main():
    """
    脚本的主入口点，包含了所有的执行逻辑。
    """
    # 保持顺序去重
    attack_order = list(dict.fromkeys(attack_order_raw))
    print(len(attack_order))
    FLAG_LENGTH = 50

    print("=" * 50)
    print("开始按照预设顺序进行多线程非顺序爆破...")
    print(f"Flag 总长度 (根据最大索引决定): {FLAG_LENGTH}")
    print(f"并发线程数: {MAX_WORKERS}")
    print(f"将要爆破的位置顺序: {attack_order}")
    print("=" * 50)

    # 初始化flag占位符
    result_flag_list = list("c9zaaaaaaaaaaaaqjaaaauaaaaaaaaaaaaaaaabaaaaaaaaaa5")

    # 外层循环：按顺序攻击指定位置
    for pos_to_attack in attack_order[8:]:
        print(f"[*] 正在爆破第 {pos_to_attack} 号位置...")
        
        results_for_position = {}
        total_chars = len(CHARSET)
        
        # 使用线程池并发测试当前位置的所有可能性
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_char = {executor.submit(test_single_char, pos_to_attack, char, result_flag_list): char for char in CHARSET}
            
            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_char):
                char_tested = future_to_char[future]
                try:
                    char, instruction_count = future.result()
                    results_for_position[char] = instruction_count
                except Exception as exc:
                    print(f'\n[!] 字符 "{char_tested}" 在测试时产生异常: {exc}')
                    results_for_position[char_tested] = -1
                
                completed_count += 1
                progress_text = f"    进度: {completed_count}/{total_chars} | 测试 '{char_tested}' -> {results_for_position.get(char_tested, 'Error')}"
                print(f"{progress_text.ljust(80)}", end="")

        print("\n")

        # 分析当前位置的结果
        valid_results = {k: v for k, v in results_for_position.items() if v != -1}
        if not valid_results:
            print(f"[!] 位置 {pos_to_attack} 爆破失败，未能收集到任何有效指令数。中止。")
            break

        best_char = max(valid_results, key=valid_results.get)
        max_count = valid_results[best_char]

        # 更新结果
        result_flag_list[pos_to_attack] = best_char

        print(f"[+] 发现位置 {pos_to_attack} 的字符: '{best_char}' (最大指令数: {max_count})")
        print(f"[*] 当前 Flag 状态: {''.join(result_flag_list)}")
        print("-" * 50)

    # 最终结果
    final_flag = "".join(result_flag_list)
    print("\n" + "=" * 50)
    print("非顺序爆破完成！")
    print(f"最终 Flag: {final_flag}")
    print("=" * 50)


# --- 脚本执行入口 ---
# 确保只有在直接运行此脚本时才执行main()函数
# 这是多线程/多进程编程中的一个重要保护措施
if __name__ == "__main__":
    main()
~~~

后面观察发现前十五个SMC比较稳定，最后一字节都是retn（0xc7），可以直接获取异或字节；从15开始的SMC经过多次比较，发现异或完开头第一个字节只有三种可能，分别是mov（0xc7）、lea（0x8d）、xor（0x83，只有四个）

~~~python
import idc
import ida_bytes

# 关键：需要安装 capstone 库 (pip install capstone)
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("="*60)
    print("错误: Capstone 库未找到!")
    print("请为IDA的Python环境安装capstone: 'python.exe -m pip install capstone'")
    print("="*60)
    # 如果导入失败，抛出异常以停止脚本执行
    raise

def is_valid_disassembly(code_bytes, base_address):
    """
    使用 Capstone 检查给定的字节码是否可以被完整、有效地反汇编。
    这是我们验证密钥是否正确的核心函数。
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    total_disassembled_size = 0
    try:
        instructions = list(md.disasm(code_bytes, base_address))
        if not instructions:
            return False
        for i in instructions:
            total_disassembled_size += i.size
        return total_disassembled_size == len(code_bytes)
    except Exception:
        return False

def decrypt_smc_functions():
    """
    IDAPython 脚本，使用两种方法解密SMC函数：
    1. (前15个) 基于`retn`指令硬编码的密钥推导。
    2. (后续) 基于函数开头的'mov'/'lea'指令推导密钥，并用Capstone验证。
    """
    
    # --- 配置区 ---
    pointer_array_ea = 0x555555559080
    function_lengths = [
        0x6D, 0x6D, 0x6C, 0x4E, 0x77, 0x62, 0x54, 0x16, 0x75, 0x0D, 
        0x61, 0x8A, 0x4C, 0x50, 0x5E, 0x71, 0x12, 0x2A, 0x6E, 0x6B, 
        0x63, 0x5D, 0x78, 0x6D, 0x10, 0x80, 0x53, 0x18, 0x70, 0x1D, 
        0x57, 0x70, 0x18, 0x4B, 0x0D, 0x69, 0x56, 0x54, 0x65, 0x5B, 
        0x4D, 0x4F, 0x71, 0x58, 0x79, 0x66, 0x13, 0x7A, 0x6E, 0x62
    ]
    # 根据你的要求，对16号及之后的函数长度进行修正
    for i in range(15, len(function_lengths)):
        function_lengths[i] -= 1
        
    num_functions = len(function_lengths)
    
    print("="*40)
    print("开始执行SMC解密脚本 (mov/lea推导)...")
    print(f"待处理函数总数: {num_functions}")
    print(f"指针数组起始于: {hex(pointer_array_ea)}")
    print("="*40)
    
    flag = ""
    # --- 主逻辑 ---
    for i in range(num_functions):
        current_pointer_ea = pointer_array_ea + (i * 8)
        func_ea = ida_bytes.get_qword(current_pointer_ea)
        func_size = function_lengths[i]
        
        if func_ea == 0 or func_ea == idaapi.BADADDR:
            print(f"[-] 警告: 在 {hex(current_pointer_ea)} 处发现无效指针，跳过。")
            continue
        
        print(f"\n[*] 正在处理第 {i+1}/{num_functions} 个函数 (地址: {hex(func_ea)}, 大小: {hex(func_size)})")
        
        encrypted_bytes = ida_bytes.get_bytes(func_ea, func_size)
        if not encrypted_bytes:
            print(f"[-] 错误: 无法从 {hex(func_ea)} 读取字节码，跳过。")
            continue
        
        xor_key = None
        decrypted_bytes = None

        if i < 15:
            # --- 方法1：对于前15个函数，使用旧的'retn'逻辑 ---
            print("  -> [方法1] 使用 'retn' 推导...")
            xor_key = encrypted_bytes[-1] ^ 0xc3
            decrypted_bytes = bytes([b ^ xor_key for b in encrypted_bytes])
        else:
            # --- 方法2：对于后续函数，使用'mov'/'lea'假设进行推导 ---
            print("  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...")
            found_key = False
            first_encrypted_byte = encrypted_bytes[0]
            
            # 定义两种假设：1. 函数以 mov (0xC7) 开头  2. 函数以 lea (0x8D) 开头
            assumptions = [
                {"opcode": 0xC7, "name": "mov"},
                {"opcode": 0x8D, "name": "lea"},
                {"opcode": 0x83, "name": "xor"}
            ]
            
            for assumption in assumptions:
                candidate_key = first_encrypted_byte ^ assumption["opcode"]
                print(f"    -> 尝试基于 '{assumption['name']}' (0x{assumption['opcode']:02X}) 推导的密钥: {hex(candidate_key)}")
                
                candidate_bytes = bytes([b ^ candidate_key for b in encrypted_bytes])
                
                # 使用Capstone验证该密钥是否能产生有效的完整汇编代码
                if is_valid_disassembly(candidate_bytes, func_ea):
                    print(f"      -> 成功! 密钥 {hex(candidate_key)} 产生有效汇编。")
                    xor_key = candidate_key
                    decrypted_bytes = candidate_bytes
                    found_key = True
                    break # 密钥已找到，无需再试其他假设
            
            if not found_key:
                print(f"  -> [!] 失败: 'mov' 和 'lea' 两种假设均未找到有效密钥。")
                xor_key = ord('*')
                decrypted_bytes = encrypted_bytes

        # --- 通用处理：Patch、重新分析并记录 flag ---
        if xor_key is not None and decrypted_bytes is not None:
            flag += chr(xor_key)
            print(f"  -> 最终密钥: {hex(xor_key)} ('{chr(xor_key)}')")
            
            ida_bytes.patch_bytes(func_ea, decrypted_bytes)
            print(f"  -> Patch成功: {len(decrypted_bytes)} 字节已写入 {hex(func_ea)}")
        else:
            print(f"  -> 跳过对函数 {hex(func_ea)} 的Patch操作。")

    print("\n" + "="*40)
    print("✅ 脚本执行完毕！")
    print(f"最终提取的 Flag: {flag}")
    print("="*40)

# --- 执行函数 ---
decrypt_smc_functions()
~~~

log如下

~~~
========================================
开始执行SMC解密脚本 (mov/lea推导)...
待处理函数总数: 50
指针数组起始于: 0x555555559080
========================================

[*] 正在处理第 1/50 个函数 (地址: 0x5555555551f0, 大小: 0x6d)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x63 ('c')
  -> Patch成功: 109 字节已写入 0x5555555551f0

[*] 正在处理第 2/50 个函数 (地址: 0x555555555260, 大小: 0x6d)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x39 ('9')
  -> Patch成功: 109 字节已写入 0x555555555260

[*] 正在处理第 3/50 个函数 (地址: 0x5555555552d0, 大小: 0x6c)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x7a ('z')
  -> Patch成功: 108 字节已写入 0x5555555552d0

[*] 正在处理第 4/50 个函数 (地址: 0x555555555340, 大小: 0x4e)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x32 ('2')
  -> Patch成功: 78 字节已写入 0x555555555340

[*] 正在处理第 5/50 个函数 (地址: 0x555555555390, 大小: 0x77)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x63 ('c')
  -> Patch成功: 119 字节已写入 0x555555555390

[*] 正在处理第 6/50 个函数 (地址: 0x555555555410, 大小: 0x62)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x6e ('n')
  -> Patch成功: 98 字节已写入 0x555555555410

[*] 正在处理第 7/50 个函数 (地址: 0x555555555480, 大小: 0x54)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x39 ('9')
  -> Patch成功: 84 字节已写入 0x555555555480

[*] 正在处理第 8/50 个函数 (地址: 0x5555555554e0, 大小: 0x16)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x6a ('j')
  -> Patch成功: 22 字节已写入 0x5555555554e0

[*] 正在处理第 9/50 个函数 (地址: 0x555555555500, 大小: 0x75)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x6d ('m')
  -> Patch成功: 117 字节已写入 0x555555555500

[*] 正在处理第 10/50 个函数 (地址: 0x555555555580, 大小: 0xd)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x76 ('v')
  -> Patch成功: 13 字节已写入 0x555555555580

[*] 正在处理第 11/50 个函数 (地址: 0x555555555590, 大小: 0x61)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x6b ('k')
  -> Patch成功: 97 字节已写入 0x555555555590

[*] 正在处理第 12/50 个函数 (地址: 0x555555555600, 大小: 0x8a)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x68 ('h')
  -> Patch成功: 138 字节已写入 0x555555555600

[*] 正在处理第 13/50 个函数 (地址: 0x555555555690, 大小: 0x4c)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x33 ('3')
  -> Patch成功: 76 字节已写入 0x555555555690

[*] 正在处理第 14/50 个函数 (地址: 0x5555555556e0, 大小: 0x50)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x30 ('0')
  -> Patch成功: 80 字节已写入 0x5555555556e0

[*] 正在处理第 15/50 个函数 (地址: 0x555555555730, 大小: 0x5e)
  -> [方法1] 使用 'retn' 推导...
  -> 最终密钥: 0x61 ('a')
  -> Patch成功: 94 字节已写入 0x555555555730

[*] 正在处理第 16/50 个函数 (地址: 0x555555555790, 大小: 0x70)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x35
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x7f
    -> 尝试基于 'xor' (0x83) 推导的密钥: 0x71
      -> 成功! 密钥 0x71 产生有效汇编。
  -> 最终密钥: 0x71 ('q')
  -> Patch成功: 112 字节已写入 0x555555555790

[*] 正在处理第 17/50 个函数 (地址: 0x555555555810, 大小: 0x11)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x20
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x6a
      -> 成功! 密钥 0x6a 产生有效汇编。
  -> 最终密钥: 0x6a ('j')
  -> Patch成功: 17 字节已写入 0x555555555810

[*] 正在处理第 18/50 个函数 (地址: 0x555555555830, 大小: 0x29)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x3d
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x77
      -> 成功! 密钥 0x77 产生有效汇编。
  -> 最终密钥: 0x77 ('w')
  -> Patch成功: 41 字节已写入 0x555555555830

[*] 正在处理第 19/50 个函数 (地址: 0x555555555860, 大小: 0x6d)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x72
      -> 成功! 密钥 0x72 产生有效汇编。
  -> 最终密钥: 0x72 ('r')
  -> Patch成功: 109 字节已写入 0x555555555860

[*] 正在处理第 20/50 个函数 (地址: 0x5555555558d0, 大小: 0x6a)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x62
      -> 成功! 密钥 0x62 产生有效汇编。
  -> 最终密钥: 0x62 ('b')
  -> Patch成功: 106 字节已写入 0x5555555558d0

[*] 正在处理第 21/50 个函数 (地址: 0x555555555940, 大小: 0x62)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x33
      -> 成功! 密钥 0x33 产生有效汇编。
  -> 最终密钥: 0x33 ('3')
  -> Patch成功: 98 字节已写入 0x555555555940

[*] 正在处理第 22/50 个函数 (地址: 0x5555555559b0, 大小: 0x5c)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x75
      -> 成功! 密钥 0x75 产生有效汇编。
  -> 最终密钥: 0x75 ('u')
  -> Patch成功: 92 字节已写入 0x5555555559b0

[*] 正在处理第 23/50 个函数 (地址: 0x555555555a10, 大小: 0x77)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x72
      -> 成功! 密钥 0x72 产生有效汇编。
  -> 最终密钥: 0x72 ('r')
  -> Patch成功: 119 字节已写入 0x555555555a10

[*] 正在处理第 24/50 个函数 (地址: 0x555555555a90, 大小: 0x6c)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x78
      -> 成功! 密钥 0x78 产生有效汇编。
  -> 最终密钥: 0x78 ('x')
  -> Patch成功: 108 字节已写入 0x555555555a90

[*] 正在处理第 25/50 个函数 (地址: 0x555555555b00, 大小: 0xf)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x30
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x7a
    -> 尝试基于 'xor' (0x83) 推导的密钥: 0x74
      -> 成功! 密钥 0x74 产生有效汇编。
  -> 最终密钥: 0x74 ('t')
  -> Patch成功: 15 字节已写入 0x555555555b00

[*] 正在处理第 26/50 个函数 (地址: 0x555555555b10, 大小: 0x7f)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x6b
      -> 成功! 密钥 0x6b 产生有效汇编。
  -> 最终密钥: 0x6b ('k')
  -> Patch成功: 127 字节已写入 0x555555555b10

[*] 正在处理第 27/50 个函数 (地址: 0x555555555b90, 大小: 0x52)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x70
      -> 成功! 密钥 0x70 产生有效汇编。
  -> 最终密钥: 0x70 ('p')
  -> Patch成功: 82 字节已写入 0x555555555b90

[*] 正在处理第 28/50 个函数 (地址: 0x555555555bf0, 大小: 0x17)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x7b
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x31
      -> 成功! 密钥 0x31 产生有效汇编。
  -> 最终密钥: 0x31 ('1')
  -> Patch成功: 23 字节已写入 0x555555555bf0

[*] 正在处理第 29/50 个函数 (地址: 0x555555555c10, 大小: 0x6f)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x30
      -> 成功! 密钥 0x30 产生有效汇编。
  -> 最终密钥: 0x30 ('0')
  -> Patch成功: 111 字节已写入 0x555555555c10

[*] 正在处理第 30/50 个函数 (地址: 0x555555555c80, 大小: 0x1c)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x35
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x7f
    -> 尝试基于 'xor' (0x83) 推导的密钥: 0x71
      -> 成功! 密钥 0x71 产生有效汇编。
  -> 最终密钥: 0x71 ('q')
  -> Patch成功: 28 字节已写入 0x555555555c80

[*] 正在处理第 31/50 个函数 (地址: 0x555555555ca0, 大小: 0x56)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x38
      -> 成功! 密钥 0x38 产生有效汇编。
  -> 最终密钥: 0x38 ('8')
  -> Patch成功: 86 字节已写入 0x555555555ca0

[*] 正在处理第 32/50 个函数 (地址: 0x555555555d00, 大小: 0x6f)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x28
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x62
      -> 成功! 密钥 0x62 产生有效汇编。
  -> 最终密钥: 0x62 ('b')
  -> Patch成功: 111 字节已写入 0x555555555d00

[*] 正在处理第 33/50 个函数 (地址: 0x555555555d70, 大小: 0x17)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x7a
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x30
      -> 成功! 密钥 0x30 产生有效汇编。
  -> 最终密钥: 0x30 ('0')
  -> Patch成功: 23 字节已写入 0x555555555d70

[*] 正在处理第 34/50 个函数 (地址: 0x555555555d90, 大小: 0x4a)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x76
      -> 成功! 密钥 0x76 产生有效汇编。
  -> 最终密钥: 0x76 ('v')
  -> Patch成功: 74 字节已写入 0x555555555d90

[*] 正在处理第 35/50 个函数 (地址: 0x555555555de0, 大小: 0xc)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x38
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x72
      -> 成功! 密钥 0x72 产生有效汇编。
  -> 最终密钥: 0x72 ('r')
  -> Patch成功: 12 字节已写入 0x555555555de0

[*] 正在处理第 36/50 个函数 (地址: 0x555555555df0, 大小: 0x68)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x5f
      -> 成功! 密钥 0x5f 产生有效汇编。
  -> 最终密钥: 0x5f ('_')
  -> Patch成功: 104 字节已写入 0x555555555df0

[*] 正在处理第 37/50 个函数 (地址: 0x555555555e60, 大小: 0x55)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x73
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x39
      -> 成功! 密钥 0x39 产生有效汇编。
  -> 最终密钥: 0x39 ('9')
  -> Patch成功: 85 字节已写入 0x555555555e60

[*] 正在处理第 38/50 个函数 (地址: 0x555555555ec0, 大小: 0x53)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x64
      -> 成功! 密钥 0x64 产生有效汇编。
  -> 最终密钥: 0x64 ('d')
  -> Patch成功: 83 字节已写入 0x555555555ec0

[*] 正在处理第 39/50 个函数 (地址: 0x555555555f20, 大小: 0x64)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x62
      -> 成功! 密钥 0x62 产生有效汇编。
  -> 最终密钥: 0x62 ('b')
  -> Patch成功: 100 字节已写入 0x555555555f20

[*] 正在处理第 40/50 个函数 (地址: 0x555555555f90, 大小: 0x5a)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x66
      -> 成功! 密钥 0x66 产生有效汇编。
  -> 最终密钥: 0x66 ('f')
  -> Patch成功: 90 字节已写入 0x555555555f90

[*] 正在处理第 41/50 个函数 (地址: 0x555555555ff0, 大小: 0x4c)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x72
      -> 成功! 密钥 0x72 产生有效汇编。
  -> 最终密钥: 0x72 ('r')
  -> Patch成功: 76 字节已写入 0x555555555ff0

[*] 正在处理第 42/50 个函数 (地址: 0x555555556040, 大小: 0x4e)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x6f
      -> 成功! 密钥 0x6f 产生有效汇编。
  -> 最终密钥: 0x6f ('o')
  -> Patch成功: 78 字节已写入 0x555555556040

[*] 正在处理第 43/50 个函数 (地址: 0x555555556090, 大小: 0x70)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x63
      -> 成功! 密钥 0x63 产生有效汇编。
  -> 最终密钥: 0x63 ('c')
  -> Patch成功: 112 字节已写入 0x555555556090

[*] 正在处理第 44/50 个函数 (地址: 0x555555556110, 大小: 0x57)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x61
      -> 成功! 密钥 0x61 产生有效汇编。
  -> 最终密钥: 0x61 ('a')
  -> Patch成功: 87 字节已写入 0x555555556110

[*] 正在处理第 45/50 个函数 (地址: 0x555555556170, 大小: 0x78)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x6c
      -> 成功! 密钥 0x6c 产生有效汇编。
  -> 最终密钥: 0x6c ('l')
  -> Patch成功: 120 字节已写入 0x555555556170

[*] 正在处理第 46/50 个函数 (地址: 0x5555555561f0, 大小: 0x65)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x6b
      -> 成功! 密钥 0x6b 产生有效汇编。
  -> 最终密钥: 0x6b ('k')
  -> Patch成功: 101 字节已写入 0x5555555561f0

[*] 正在处理第 47/50 个函数 (地址: 0x555555556260, 大小: 0x12)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x2a
    -> 尝试基于 'lea' (0x8D) 推导的密钥: 0x60
    -> 尝试基于 'xor' (0x83) 推导的密钥: 0x6e
      -> 成功! 密钥 0x6e 产生有效汇编。
  -> 最终密钥: 0x6e ('n')
  -> Patch成功: 18 字节已写入 0x555555556260

[*] 正在处理第 48/50 个函数 (地址: 0x555555556280, 大小: 0x79)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x31
      -> 成功! 密钥 0x31 产生有效汇编。
  -> 最终密钥: 0x31 ('1')
  -> Patch成功: 121 字节已写入 0x555555556280

[*] 正在处理第 49/50 个函数 (地址: 0x555555556300, 大小: 0x6d)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x76
      -> 成功! 密钥 0x76 产生有效汇编。
  -> 最终密钥: 0x76 ('v')
  -> Patch成功: 109 字节已写入 0x555555556300

[*] 正在处理第 50/50 个函数 (地址: 0x555555556370, 大小: 0x61)
  -> [方法2] 使用 'mov'/'lea' 指令推导密钥...
    -> 尝试基于 'mov' (0xC7) 推导的密钥: 0x35
      -> 成功! 密钥 0x35 产生有效汇编。
  -> 最终密钥: 0x35 ('5')
  -> Patch成功: 97 字节已写入 0x555555556370

========================================
✅ 脚本执行完毕！
最终提取的 Flag: c9z2cn9jmvkh30aqjwrb3urxtkp10q8b0vr_9dbfrocalkn1v5
========================================
~~~

不需要你写代码，告诉ai怎么写就行