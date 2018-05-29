#ifndef TRUSTCHAT_DEMO_H
#define TRUSTCHAT_DEMO_H

enum  trustchat_demo_type
{
	DTYPE_TRUSTCHAT_DEMO=0x3001,
	DTYPE_TRUSTCHAT_EXPAND=0x3010,
	DTYPE_TRUSTCHAT_STORE=0x3020
};

enum trustchat_demo_subtype
{
	SUBTYPE_LOGIN_INFO=0x01,
	SUBTYPE_VERIFY_RETURN,
	SUBTYPE_CHAT_MSG,	
	SUBTYPE_DATA_KEY,	
};

enum trustchat_MSG_FLAG 
{
	TRUSTMSG_NORMAL=0x01,      // 
	TRUSTMSG_PRIVATE=0x02,     // private data,should be crypted
	TRUSTMSG_CRYPT=0x10,       //
	TRUSTMSG_SIGN=0x20   
};

struct login_info
{
        char user[DIGEST_SIZE];    //用户名称
        char passwd[DIGEST_SIZE];  //用户口令
        char nonce[DIGEST_SIZE];   //随机数 
} __attribute__((packed));

struct verify_return
{
        int retval;    //返回值，-1为不存在用户，0为口令不正确，1为成功
        int ret_data_size;   //返回信息的大小
        BYTE * ret_data;   //返回信息的内容
        char nonce[DIGEST_SIZE];  //随机值
} __attribute__((packed));

struct chat_msg{
	BYTE msg_head[8];        // should be TRUSTMSG
	int msg_size;
	char * msg;               //消息内容，以’\0’结尾 
}__attribute__((packed));


#endif
