#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"
#include "file_struct.h"
#include "vtcm_script.h"

#include "app_struct.h"
#include "expand_struct.h"
#include "store_struct.h"

BYTE Buf[DIGEST_SIZE*16];

int key_switch_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int key_switch_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	void * data_msg;
	int i;
	int type;
	int subtype;


	for(i=0;i<3000*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=ex_module_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		type=message_get_type(recv_msg);
		subtype=message_get_subtype(recv_msg);
		if(!memdb_find_recordtype(type,subtype))
		{
			printf("message format (%d %d) is not registered!\n",
				message_get_type(recv_msg),message_get_subtype(recv_msg));
			continue;
		}
		if((type==DTYPE_TRUSTCHAT_DEMO)&&(subtype==SUBTYPE_CHAT_MSG))
		{
			data_msg=recv_msg;
			if(message_get_flag(recv_msg) &MSG_FLAG_CRYPT)
				proc_key_decrypt(sub_proc,recv_msg);
			else
				proc_key_encrypt(sub_proc,recv_msg);
		}
		if((type==DTYPE_VTCM_SCRIPT)&&(subtype==VTCM_SCRIPT_RET))
		{
			if(message_get_flag(recv_msg) &MSG_FLAG_CRYPT)
				proc_key_recover(sub_proc,data_msg);
			else
				proc_key_send(sub_proc,data_msg);
		}
	}
	return 0;
}

int proc_key_encrypt(void * sub_proc,void * recv_msg)
{
	char local_uuid[DIGEST_SIZE];
	char proc_name[DIGEST_SIZE];
	char user[DIGEST_SIZE];
	int i;
	int ret;
	struct chat_msg * chat_msg;		
	struct msg_info * expand_info;
	struct store_msg * store_message;
	DB_RECORD * db_record;
	MSG_EXPAND * msg_expand;

	printf("begin proc session key generate and encrypt \n");

	struct vtcm_script_call * tcm_call;
	int fd;

	BYTE symm_key[32];

	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);
	ret=proc_share_data_getvalue("user_name",user);

	ret=message_get_record(recv_msg,&chat_msg,0);
	if(ret<0)
		return ret;
	
	ret=message_get_define_expand(recv_msg,&msg_expand,DTYPE_TRUSTCHAT_EXPAND,SUBTYPE_EXPAND_INFO);	
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
		return -EINVAL;
	expand_info=msg_expand->expand;

	fd=open("/dev/urandom",O_RDONLY);
	if(fd<0)
		return -EINVAL;

	read(fd,symm_key,32);
	
	close(fd);

	fd=open("session.key",O_WRONLY|O_TRUNC|O_CREAT,0666);
	if(fd<0)
		return -EIO;
	write(fd,symm_key,32);
	close(fd);

	tcm_call=Talloc0(sizeof(*tcm_call));
	if(tcm_call==NULL)
		return -ENOMEM;
	Strncpy(tcm_call->name,"script/sm2encrypt.cmd",DIGEST_SIZE);

	tcm_call->param_num=2;

	tcm_call->params=Talloc0(DIGEST_SIZE*2);
	if(tcm_call->params==NULL)
		return -ENOMEM;
	Strncpy(tcm_call->params,"key/",DIGEST_SIZE);
	Strncat(tcm_call->params,expand_info->receiver,DIGEST_SIZE);
	Strncat(tcm_call->params,"_sm2.key",DIGEST_SIZE);
	Strncpy(tcm_call->params+32,"123",DIGEST_SIZE);

	void * new_msg=message_create(DTYPE_VTCM_SCRIPT,VTCM_SCRIPT_CALL,NULL);
	if(new_msg==NULL)
		return -EINVAL;
	message_add_record(new_msg,tcm_call);
	
	ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

int proc_key_decrypt(void * sub_proc,void * message)
{
	int i;
	int ret;
	int fd;
	printf("begin proc session key decrypt! \n");
	
	MSG_EXPAND * msg_expand;	
	struct sized_bindata * key_buf;
	struct vtcm_script_call * tcm_call;
	struct msg_info * expand_info;

	ret=message_get_define_expand(message,&msg_expand,DTYPE_TRUSTCHAT_EXPAND,SUBTYPE_EXPAND_INFO);	
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
		return -EINVAL;
	expand_info=msg_expand->expand;

	ret=message_remove_expand(message,DTYPE_MESSAGE,SUBTYPE_SIZED_BINDATA,&msg_expand);
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
		return -EINVAL;
	key_buf=msg_expand->expand;

	fd=open("switch.key",O_WRONLY|O_TRUNC|O_CREAT,0666);
	if(fd<0)
		return -EINVAL;

	ret=write(fd,key_buf->bindata,key_buf->size);
	if(ret!= key_buf->size)
	{
		printf("write switch key failed!\n");
		return -EINVAL;
	}
	close(fd);

	tcm_call=Talloc0(sizeof(*tcm_call));
	if(tcm_call==NULL)
		return -ENOMEM;
	Strncpy(tcm_call->name,"script/sm2decrypt.cmd",DIGEST_SIZE);

	tcm_call->param_num=2;

	tcm_call->params=Talloc0(DIGEST_SIZE*2);
	if(tcm_call->params==NULL)
		return -ENOMEM;
	Strncpy(tcm_call->params,"key/",DIGEST_SIZE);
	Strncat(tcm_call->params,expand_info->receiver,DIGEST_SIZE);
	Strncat(tcm_call->params,"_sm2.key",DIGEST_SIZE);
	Strncpy(tcm_call->params+32,"123",DIGEST_SIZE);

	void * new_msg=message_create(DTYPE_VTCM_SCRIPT,VTCM_SCRIPT_CALL,NULL);
	if(new_msg==NULL)
		return -EINVAL;
	message_add_record(new_msg,tcm_call);
	
	ex_module_sendmsg(sub_proc,new_msg);
	return ret;
	
}

int proc_key_send(void * sub_proc,void * message)
{
	int i;
	int ret;
	printf("begin proc key send \n");

	struct sized_bindata * key_buf;
	int fd;

	fd=open("switch.key",O_RDONLY);
	if(fd<0)
		return -EINVAL;

	ret=read(fd,Buf,DIGEST_SIZE*12+1);
	if(ret>DIGEST_SIZE*12)
	{
		printf("switch key too large!\n");
		return -EINVAL;
	}
	close(fd);

	key_buf=Talloc0(sizeof(*key_buf));
	if(key_buf==NULL)
		return -ENOMEM;
	key_buf->size=ret;
	key_buf->bindata=Talloc0(key_buf->size);
	if(key_buf->bindata==NULL)
		return -ENOMEM;
	Memcpy(key_buf->bindata,Buf,key_buf->size);

	ret=message_add_expand_data(message,DTYPE_MESSAGE,SUBTYPE_SIZED_BINDATA,key_buf);
	if(ret<0)
		return -EINVAL;
	ret=ex_module_sendmsg(sub_proc,message);
		
	system("rm switch.key");

	return ret;
}

int proc_key_recover(void * sub_proc,void * message)
{
	int i;
	int ret;
	ret=ex_module_sendmsg(sub_proc,message);
	return ret;
	
}
