#ifndef CRYPTO_DEMO_SERVERSTRUCT_H
#define CRYPTO_DEMO_SERVERSTRUCT_H

struct user_address
{
        char user[DIGEST_SIZE];  //用户名称
        char addr[DIGEST_SIZE];  //用户后端地址：
} __attribute__((packed));

#endif
