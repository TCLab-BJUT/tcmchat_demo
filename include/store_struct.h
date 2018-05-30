#ifndef TRUSTCHAT_DEMO_STORESTRUCT_H
#define TRUSTCHAT_DEMO_STORESTRUCT_H

enum trustchat_expand_store
{
	SUBTYPE_STORE_MSG=0x01,	
	SUBTYPE_STORE_USERADDR=0x10,
};

enum trustchat_RECV_FLAG
{
	CHAT_MSG_SELF=0x01,
	CHAT_MSG_RECV=0x02,
	CHAT_MSG_DECRYPT=0x10,
	CHAT_MSG_VERIFY=0x20,
	CHAT_MSG_VERIFY_FAIL=0x0100,
	CHAT_MSG_DATA_ERR=0x0200	
};

struct store_msg{
	struct msg_info *info;
	struct chat_msg * msg;
	int    store_flags;
	struct session_key * key;
	struct sign_data * sign;
}__attribute__((packed));

struct user_address
{
        char user[DIGEST_SIZE];  //用户名称
        char addr[DIGEST_SIZE];  //用户后端地址：
} __attribute__((packed));

#endif
