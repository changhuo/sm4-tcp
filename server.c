#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "sm4.h"

// 配置项（不变）
#define PORT 8888
#define BUF_SIZE 1024
#define SM4_KEY_LEN 16
#define RSA_KEY_SIZE 2048
#define RSA_ENCRYPT_LEN 256

// 全局变量（不变）
uint8_t g_sm4_key[SM4_KEY_LEN] = {0};
int g_client_fd = -1;

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

// RSA私钥解密（不变）
int rsa_pri_decrypt(uint8_t *in, uint8_t *out, const char *priv_key_path) {
    printf("\n[RSA解密] 开始解密SM4密钥...\n");
    FILE *fp = fopen(priv_key_path, "r");
    if (!fp) {
        perror("[RSA解密] 打开私钥文件失败");
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "[RSA解密] 加载私钥失败\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "[RSA解密] 初始化上下文失败\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "[RSA解密] 设置填充方式失败\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    size_t out_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, in, RSA_ENCRYPT_LEN) <= 0) {
        fprintf(stderr, "[RSA解密] 计算解密长度失败\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    printf("[RSA解密] 预期解密长度：%zu字节（SM4标准16字节）\n", out_len);
    if (EVP_PKEY_decrypt(ctx, out, &out_len, in, RSA_ENCRYPT_LEN) <= 0) {
        fprintf(stderr, "[RSA解密] 解密失败\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (out_len != SM4_KEY_LEN) {
        printf("[RSA解密] 失败！解密长度=%zu（预期16）\n", out_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    printf("[RSA解密] 成功！解密出SM4密钥（16进制）：");
    for (int i = 0; i < SM4_KEY_LEN; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return SM4_KEY_LEN;
}

// 接收消息线程（核心修改：客户端消息后增加换行）
void *recv_msg_thread(void *arg) {
    int fd = *(int *)arg;
    char buf[BUF_SIZE] = {0};
    uint8_t cipher[BUF_SIZE] = {0};
    
    printf("\n[聊天线程] 启动！等待客户端消息...\n");
    while (1) {
        memset(buf, 0, sizeof(buf));
        memset(cipher, 0, sizeof(cipher));
        
        // 接收密文长度（不变）
        uint32_t cipher_len = 0;
        if (recv_all(fd, &cipher_len, sizeof(cipher_len)) <= 0) {
            printf("[聊天线程] 客户端断开连接！\n");
            g_client_fd = -1;
            close(fd);
            pthread_exit(NULL);
        }
        cipher_len = ntohl(cipher_len);
        printf("[SM4解密] 待解密密文长度：%d字节\n", cipher_len);
        
        // 接收密文（不变）
        if (recv_all(fd, cipher, cipher_len) <= 0) {
            printf("[聊天线程] 接收密文失败！\n");
            g_client_fd = -1;
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

        // ========== 核心修改：客户端消息后增加换行 ==========
        printf("\n===== 客户端消息 =====\n");
        printf("客户端: %s\n", buf);
        printf("=====================\n\n");
        printf("我：");
        fflush(stdout);

        // 检测退出（不变）
        if (strcmp(buf, "exit") == 0) {
            printf("[聊天线程] 客户端退出，线程结束！\n");
            g_client_fd = -1;
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
int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[TCP] 创建套接字失败");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[TCP] 绑定端口失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 5) < 0) {
        perror("[TCP] 监听失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[TCP] 服务端启动成功，监听端口%d...\n", PORT);
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    g_client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (g_client_fd < 0) {
        perror("[TCP] 接受连接失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[TCP] 客户端连接成功！IP：%s，端口：%d\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    // 接收加密的SM4密钥（不变）
    uint8_t encrypted_sm4_key[RSA_ENCRYPT_LEN] = {0};
    printf("\n===== 开始接收加密的SM4密钥 =====\n");
    if (recv_all(g_client_fd, encrypted_sm4_key, RSA_ENCRYPT_LEN) <= 0) {
        printf("[密钥交换] 接收加密SM4密钥失败！\n");
        close(g_client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (rsa_pri_decrypt(encrypted_sm4_key, g_sm4_key, "priv.pem") != SM4_KEY_LEN) {
        printf("[密钥交换] RSA解密失败！\n");
        close(g_client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("\n===== 密钥交换完成 =====\n");
    printf("最终协商的SM4密钥（16进制）：");
    for (int i = 0; i < SM4_KEY_LEN; i++) {
        printf("%02x", g_sm4_key[i]);
    }
    printf("\n开始SM4加密聊天（输入exit退出）...\n");
    printf("我：");
    fflush(stdout);
    
    // 启动接收线程（不变）
    pthread_t recv_tid;
    if (pthread_create(&recv_tid, NULL, recv_msg_thread, &g_client_fd) != 0) {
        perror("[线程] 创建接收线程失败");
        close(g_client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // 主线程发送消息（不变）
    char msg[BUF_SIZE] = {0};
    while (1) {
        fgets(msg, sizeof(msg), stdin);
        msg[strcspn(msg, "\n")] = '\0';
        if (send_encrypt_msg(g_client_fd, msg) < 0) {
            printf("[发送] 消息发送失败！\n");
            break;
        }
        if (strcmp(msg, "exit") == 0) {
            printf("[服务端] 退出聊天！\n");
            break;
        }
        if (g_client_fd < 0) {
            printf("[服务端] 客户端已断开，退出！\n");
            break;
        }
        printf("我：");
        fflush(stdout);
    }
    
    // 清理资源（不变）
    close(g_client_fd);
    close(server_fd);
    pthread_cancel(recv_tid);
    pthread_join(recv_tid, NULL);
    printf("[服务端] 已退出！\n");
    return 0;
}
