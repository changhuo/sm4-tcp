#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// SM4核心参数
#define SM4_BLOCK_SIZE 16    // 分组长度（16字节）
#define SM4_KEY_SIZE 16      // 密钥长度（16字节）
#define SM4_ROUNDS 32        // 加密轮数

// PKCS7填充/去填充函数
int sm4_pkcs7_pad(uint8_t *in, int in_len, uint8_t *out, int max_out_len);
int sm4_pkcs7_unpad(uint8_t *in, int in_len, uint8_t *out);

// SM4 ECB模式加密（无IV，适合简单聊天场景）
// 返回值：密文长度（失败返回-1）
int sm4_encrypt_ecb(uint8_t *in, int in_len, uint8_t *key, uint8_t *out);

// SM4 ECB模式解密
// 返回值：明文长度（去填充后，失败返回-1）
int sm4_decrypt_ecb(uint8_t *in, int in_len, uint8_t *key, uint8_t *out);

#endif // SM4_H
