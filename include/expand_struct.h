#ifndef TRUSTCHAT_DEMO_EXPANDSTRUCT_H
#define TRUSTCHAT_DEMO_EXPANDSTRUCT_H

enum trustchat_expand_subtype
{
	SUBTYPE_EXPAND_INFO=0x01,
	SUBTYPE_EXPAND_KEY,
	SUBTYPE_EXPAND_SIGN	
};

struct msg_info{
	BYTE uuid[DIGEST_SIZE];
	char sender[DIGEST_SIZE]; //发送者名称
	char receiver[DIGEST_SIZE]; //接收者名称
	int   time;               //消息发送时间
	int   flags; 
}__attribute__((packed));

struct session_key{
	BYTE asym_key_uuid;
	int key_size;
	BYTE * key_data;
}__attribute__((packed));

struct sign_data{
	BYTE sign_key_uuid;
	int  sign_result;        // 0 is not verify, 1 is verify succeed, -1 is verify fail
	int sign_size;
	BYTE * sign_data;
}__attribute__((packed));

#endif
