#include "sm4.h"
// SM4标准S盒
static const uint8_t sm4_sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
// 系统参数FK
static const uint32_t sm4_FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
// 固定参数CK
static const uint32_t sm4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};
// 循环左移
static uint32_t sm4_rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
// 字节替换
static uint32_t sm4_sub_byte(uint32_t x) {
    uint8_t *b = (uint8_t *)&x;
    b[0] = sm4_sbox[b[0]];
    b[1] = sm4_sbox[b[1]];
    b[2] = sm4_sbox[b[2]];
    b[3] = sm4_sbox[b[3]];
    return x;
}
// 线性变换
static uint32_t sm4_linear_transform(uint32_t x) {
    return x ^ sm4_rol(x, 2) ^ sm4_rol(x, 10) ^ sm4_rol(x, 18) ^ sm4_rol(x, 24);
}
// 轮函数
static uint32_t sm4_round_func(uint32_t x, uint32_t rk) {
    return x ^ sm4_linear_transform(sm4_sub_byte(x ^ rk));
}
// 密钥扩展（生成32轮轮密钥）
static void sm4_key_expansion(uint8_t *key, uint32_t rk[32]) {
    uint32_t mk[4];
    // 转换密钥为大端32位整数（SM4标准要求）
    for (int i = 0; i < 4; i++) {
        mk[i] = (uint32_t)key[i*4] << 24 | (uint32_t)key[i*4+1] << 16 | 
                (uint32_t)key[i*4+2] << 8 | (uint32_t)key[i*4+3];
    }
    uint32_t k[36];
    for (int i = 0; i < 4; i++) k[i] = mk[i] ^ sm4_FK[i];
    for (int i = 0; i < 32; i++) {
        k[i+4] = k[i] ^ sm4_round_func(k[i+1] ^ k[i+2] ^ k[i+3] ^ sm4_CK[i], 0);
        rk[i] = k[i+4];
    }
}
// 单分组加密（16字节）
static void sm4_encrypt_block(uint8_t *in, uint8_t *out, uint32_t rk[32]) {
    uint32_t x[36];
    // 转换输入为大端32位整数
    for (int i = 0; i < 4; i++) {
        x[i] = (uint32_t)in[i*4] << 24 | (uint32_t)in[i*4+1] << 16 | 
                (uint32_t)in[i*4+2] << 8 | (uint32_t)in[i*4+3];
    }
    // 32轮加密
    for (int i = 0; i < 32; i++) {
        x[i+4] = x[i] ^ sm4_round_func(x[i+1] ^ x[i+2] ^ x[i+3] ^ rk[i], 0);
    }
    // 输出逆序转换
    for (int i = 0; i < 4; i++) {
        uint32_t val = x[35 - i];
        out[i*4] = (val >> 24) & 0xff;
        out[i*4+1] = (val >> 16) & 0xff;
        out[i*4+2] = (val >> 8) & 0xff;
        out[i*4+3] = val & 0xff;
    }
}
// 单分组解密（16字节）
static void sm4_decrypt_block(uint8_t *in, uint8_t *out, uint32_t rk[32]) {
    uint32_t x[36];
    // 转换输入为大端32位整数
    for (int i = 0; i < 4; i++) {
        x[i] = (uint32_t)in[i*4] << 24 | (uint32_t)in[i*4+1] << 16 | 
                (uint32_t)in[i*4+2] << 8 | (uint32_t)in[i*4+3];
    }
    // 32轮解密（使用逆序轮密钥）
    for (int i = 0; i < 32; i++) {
        x[i+4] = x[i] ^ sm4_round_func(x[i+1] ^ x[i+2] ^ x[i+3] ^ rk[31 - i], 0);
    }
    // 输出逆序转换
    for (int i = 0; i < 4; i++) {
        uint32_t val = x[35 - i];
        out[i*4] = (val >> 24) & 0xff;
        out[i*4+1] = (val >> 16) & 0xff;
        out[i*4+2] = (val >> 8) & 0xff;
        out[i*4+3] = val & 0xff;
    }
}
// PKCS7填充（核心修改：明文长度为16字节倍数时，强制填充16个0x10，符合标准）
int sm4_pkcs7_pad(uint8_t *in, int in_len, uint8_t *out, int max_out_len) {
    int pad_len = SM4_BLOCK_SIZE - (in_len % SM4_BLOCK_SIZE);
    // 关键修复：若pad_len为0（长度对齐），强制填充1个完整块（16字节）
    if (pad_len == 0) {
        pad_len = SM4_BLOCK_SIZE;
    }
    int total_len = in_len + pad_len;
    if (total_len > max_out_len) return -1;
    memcpy(out, in, in_len);
    memset(out + in_len, pad_len, pad_len); // 填充字节值=填充长度
    return total_len;
}
// PKCS7去填充（无修改，逻辑适配修复后的填充）
int sm4_pkcs7_unpad(uint8_t *in, int in_len, uint8_t *out) {
    if (in_len % SM4_BLOCK_SIZE != 0 || in_len == 0) return -1;
    uint8_t pad_len = in[in_len - 1];
    // 验证填充长度合法性（1~16字节）
    if (pad_len > SM4_BLOCK_SIZE || pad_len == 0) return -1;
    // 验证所有填充字节是否等于填充长度（防止篡改）
    for (int i = in_len - pad_len; i < in_len; i++) {
        if (in[i] != pad_len) return -1;
    }
    memcpy(out, in, in_len - pad_len);
    return in_len - pad_len;
}
// SM4 ECB加密（核心修复：内存分配适配PKCS7强制填充，解决16位明文失败问题）
int sm4_encrypt_ecb(uint8_t *in, int in_len, uint8_t *key, uint8_t *out) {
    if (!in || !key || !out || in_len < 0) return -1;
    
    // 修复1：分配足够内存（最大需额外填充16字节，避免空间不足）
    int max_padded_len = in_len + SM4_BLOCK_SIZE;
    uint8_t *padded_in = malloc(max_padded_len);
    if (!padded_in) return -1;
    
    // 修复2：通过sm4_pkcs7_pad返回值获取实际填充后长度（而非提前计算）
    int pad_ret = sm4_pkcs7_pad(in, in_len, padded_in, max_padded_len);
    if (pad_ret < 0) { 
        free(padded_in); 
        return -1; 
    }
    int padded_len = pad_ret; // 实际填充后长度（16位明文对应32字节）
    
    // 生成轮密钥
    uint32_t rk[32];
    sm4_key_expansion(key, rk);
    // 分块加密
    for (int i = 0; i < padded_len; i += SM4_BLOCK_SIZE) {
        sm4_encrypt_block(padded_in + i, out + i, rk);
    }
    free(padded_in);
    return padded_len;
}
// SM4 ECB解密（无修改）
int sm4_decrypt_ecb(uint8_t *in, int in_len, uint8_t *key, uint8_t *out) {
    if (!in || !key || !out || in_len <= 0 || in_len % SM4_BLOCK_SIZE != 0) return -1;
    // 生成轮密钥
    uint32_t rk[32];
    sm4_key_expansion(key, rk);
    // 分块解密（得到填充后的明文）
    uint8_t *dec_padded = malloc(in_len);
    if (!dec_padded) return -1;
    for (int i = 0; i < in_len; i += SM4_BLOCK_SIZE) {
        sm4_decrypt_block(in + i, dec_padded + i, rk);
    }
    // 去填充（修复后可正确处理16字节填充）
    int plain_len = sm4_pkcs7_unpad(dec_padded, in_len, out);
    free(dec_padded);
    return plain_len;
}
