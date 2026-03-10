#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "sm4.h"

// 配置项（不变）
#define PORT 8888
#define BUF_SIZE 1024
#define SM4_KEY_LEN 16
#define RSA_ENCRYPT_LEN 256

// 全局变量（不变）
uint8_t g_sm4_key[SM4_KEY_LEN] = {0};
int g_server_fd = -1;

// 生成SM4密钥（不变）
int generate_sm4_key(uint8_t *key) {
    printf("\n[SM4密钥生成] 开始生成16字节（128位）随机密钥...\n");
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("[SM4密钥生成] 打开随机设备失败");
        return -1;
    }
    ssize_t n = read(fd, key, SM4_KEY_LEN);
    close(fd);
    if (n != SM4_KEY_LEN) {
        printf("[SM4密钥生成] 失败！读取%d字节（预期16）\n", (int)n);
        return -1;
    }
    printf("[SM4密钥生成] 成功！密钥（16进制）：");
    for (int i = 0; i < SM4_KEY_LEN; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    return 0;
}

// RSA公钥加密（不变）
int rsa_pub_encrypt(uint8_t *in, uint8_t *out, const char *pub_key_path) {
    printf("\n[RSA加密] 开始加密SM4密钥...\n");
    FILE *fp = fopen(pub_key_path, "r");
    if (!fp) {
        perror("[RSA加密] 打开公钥文件失败");
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "[RSA加密] 加载公钥失败\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "[RSA加密] 初始化上下文失败\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "[RSA加密] 设置填充方式失败\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    size_t out_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, in, SM4_KEY_LEN) <= 0) {
        fprintf(stderr, "[RSA加密] 计算加密长度失败\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    printf("[RSA加密] 预期加密长度：%zu字节（2048位RSA标准）\n", out_len);
    if (EVP_PKEY_encrypt(ctx, out, &out_len, in, SM4_KEY_LEN) <= 0) {
        fprintf(stderr, "[RSA加密] 加密失败\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (out_len != RSA_ENCRYPT_LEN) {
        printf("[RSA加密] 失败！加密长度=%zu（预期256）\n", out_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    printf("[RSA加密] 成功！加密后长度：%zu字节\n", out_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return RSA_ENCRYPT_LEN;
}

// 发送加密SM4密钥（不变）
int send_encrypted_sm4_key(int fd) {
    uint8_t encrypted_key[RSA_ENCRYPT_LEN] = {0};
    if (rsa_pub_encrypt(g_sm4_key, encrypted_key, "pub.pem") != RSA_ENCRYPT_LEN) {
        printf("[密钥发送] RSA加密失败！\n");
        return -1;
    }
    printf("\n[TCP发送] 开始发送256字节加密SM4密钥...\n");
    ssize_t n = send(fd, encrypted_key, RSA_ENCRYPT_LEN, 0);
    if (n != RSA_ENCRYPT_LEN) {
        printf("[TCP发送] 失败！发送%d字节（预期256）\n", (int)n);
        return -1;
    }
    printf("[TCP发送] 成功！共发送%d字节\n", (int)n);
    return 0;
}

// 循环接收数据（不变）
ssize_t recv_all(int fd, void *buf, size_t len) {
    size_t total = 0;
    char *p = (char *)buf;
    if (len != 4) {
        printf("[TCP接收] 开始接收%d字节数据...\n", (int)len);
    }
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n <= 0) {
            printf("[TCP接收] 失败！已接收%zu字节，需要%zu字节\n", total, len);
            return -1;
        }
        total += n;
        if (len != 4) {
            printf("[TCP接收] 进度：%zu/%zu字节\n", total, len);
        }
    }
    if (len != 4) {
        printf("[TCP接收] 完成！共接收%zu字节\n", total);
    }
    return total;
}

// 接收消息线程（核心修改：服务端消息后增加换行）
void *recv_msg_thread(void *arg) {
    int fd = *(int *)arg;
    char buf[BUF_SIZE] = {0};
    uint8_t cipher[BUF_SIZE] = {0};
    
    printf("\n[聊天线程] 启动！等待服务端消息...\n");
    while (1) {
        memset(buf, 0, sizeof(buf));
        memset(cipher, 0, sizeof(cipher));
        
        // 接收密文长度（不变）
        uint32_t cipher_len = 0;
        if (recv_all(fd, &cipher_len, sizeof(cipher_len)) <= 0) {
            printf("[聊天线程] 服务端断开连接！\n");
            g_server_fd = -1;
            close(fd);
            pthread_exit(NULL);
        }
        cipher_len = ntohl(cipher_len);
        printf("[SM4解密] 待解密密文长度：%d字节\n", cipher_len);
        
        // 接收密文（不变）
        if (recv_all(fd, cipher, cipher_len) <= 0) {
            printf("[聊天线程] 接收密文失败！\n");
            g_server_fd = -1;
            close(fd);
            pthread_exit(NULL);
        }
        printf("[SM4解密] 收到密文（十六进制）：");
        for (int i = 0; i < cipher_len; i++) {
            printf("%02x", cipher[i]);
        }
        printf("\n");
        
        // SM4解密（不变）
        int plain_len = sm4_decrypt_ecb(cipher, cipher_len, g_sm4_key, (uint8_t *)buf);
        if (plain_len < 0) {
            printf("[SM4解密] 解密失败！\n");
            continue;
        }

        // ========== 核心修改：服务端消息后增加换行 ==========
        printf("\n===== 服务端消息 =====\n");
        printf("服务端: %s\n", buf);
        printf("=====================\n\n");
        printf("我：");
        fflush(stdout);

        // 检测退出（不变）
        if (strcmp(buf, "exit") == 0) {
            printf("[聊天线程] 服务端退出，线程结束！\n");
            g_server_fd = -1;
            close(fd);
            pthread_exit(NULL);
        }
    }
    return NULL;
}

// 发送加密消息（核心修改：自身消息单独换行）
int send_encrypt_msg(int fd, const char *msg) {
    if (fd < 0 || !msg || g_sm4_key[0] == 0) {
        printf("[SM4加密] 发送失败！参数错误或SM4密钥未初始化\n");
        return -1;
    }
    uint8_t cipher[BUF_SIZE] = {0};
    int cipher_len = sm4_encrypt_ecb((uint8_t *)msg, strlen(msg), g_sm4_key, cipher);
    if (cipher_len < 0) {
        printf("[SM4加密] 加密失败！\n");
        return -1;
    }
    printf("[SM4加密] 明文：%s → 密文长度：%d字节\n", msg, cipher_len);
    printf("[SM4加密] 密文（十六进制）：");
    for (int i = 0; i < cipher_len; i++) {
        printf("%02x", cipher[i]);
    }
    printf("\n");
    
    // 发送密文长度（不变）
    uint32_t net_len = htonl(cipher_len);
    if (send(fd, &net_len, sizeof(net_len), 0) != sizeof(net_len)) {
        printf("[SM4加密] 发送长度失败！\n");
        return -1;
    }
    // 发送密文（不变）
    if (send(fd, cipher, cipher_len, 0) != cipher_len) {
        printf("[SM4加密] 发送密文失败！\n");
        return -1;
    }
    printf("[SM4加密] 发送成功！\n");

    // ========== 核心修改：自身消息单独换行 ==========
    printf("\n===== 我发送的消息 =====\n");
    printf("我: %s\n", msg);
    printf("=======================\n\n");

    return 0;
}

// 主函数（不变）
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "使用方法：%s <服务端IP>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const char *server_ip = argv[1];
    
    printf("===== 客户端启动 =====\n");
    if (generate_sm4_key(g_sm4_key) < 0) {
        printf("[客户端] 生成SM4密钥失败！\n");
        exit(EXIT_FAILURE);
    }
    
    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        perror("[TCP] 创建套接字失败");
        exit(EXIT_FAILURE);
    }
    printf("[TCP] 套接字创建成功（fd=%d）\n", g_server_fd);
    
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT)
    };
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "[TCP] 无效的IP地址：%s\n", server_ip);
        close(g_server_fd);
        exit(EXIT_FAILURE);
    }
    printf("\n[TCP] 连接服务端 %s:%d...\n", server_ip, PORT);
    if (connect(g_server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[TCP] 连接失败");
        close(g_server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[TCP] 连接成功！\n");
    
    printf("\n===== 开始发送加密的SM4密钥 =====\n");
    if (send_encrypted_sm4_key(g_server_fd) < 0) {
        printf("[密钥交换] 发送失败！\n");
        close(g_server_fd);
        exit(EXIT_FAILURE);
    }
    printf("\n===== 密钥交换完成 =====\n");
    printf("本地SM4密钥（16进制）：");
    for (int i = 0; i < SM4_KEY_LEN; i++) {
        printf("%02x", g_sm4_key[i]);
    }
    printf("\n开始SM4加密聊天（输入exit退出）...\n");
    printf("我：");
    fflush(stdout);
    
    pthread_t recv_tid;
    if (pthread_create(&recv_tid, NULL, recv_msg_thread, &g_server_fd) != 0) {
        perror("[线程] 创建接收线程失败");
        close(g_server_fd);
        exit(EXIT_FAILURE);
    }
    
    char msg[BUF_SIZE] = {0};
    while (1) {
        fgets(msg, sizeof(msg), stdin);
        msg[strcspn(msg, "\n")] = '\0';
        if (send_encrypt_msg(g_server_fd, msg) < 0) {
            printf("[发送] 消息发送失败！\n");
            break;
        }
        if (strcmp(msg, "exit") == 0) {
            printf("[客户端] 退出聊天！\n");
            break;
        }
        if (g_server_fd < 0) {
            printf("[客户端] 服务端已断开，退出！\n");
            break;
        }
        printf("我：");
        fflush(stdout);
    }
    
    close(g_server_fd);
    pthread_cancel(recv_tid);
    pthread_join(recv_tid, NULL);
    printf("[客户端] 已退出！\n");
    return 0;
}
