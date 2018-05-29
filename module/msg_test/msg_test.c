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
#include "string.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"
#include "app_struct.h"
#include "expand_struct.h"
#include "store_struct.h"

BYTE Buf[128];
void * proc_gen_chatmsg(char * msg_str,char * receiver,int flags, void *recv_msg);
int  proc_store_msg(void * msg);
int msg_test_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int msg_test_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	int type;
	int subtype;
	struct start_para * start_para=para;
	int state=0;
	
        struct login_info login_data;
	if(start_para->argc <3)
	{
		printf("error test msg! should be %s user_name passwd!\n",start_para->argv[0]);
		return -EINVAL;
	}
	Strncpy(login_data.user,start_para->argv[1],DIGEST_SIZE);	
	Strncpy(login_data.passwd,start_para->argv[2],DIGEST_SIZE);	
	Memset(login_data.nonce,0,DIGEST_SIZE);	

	proc_share_data_setvalue("user_name",login_data.user);

  
        void * send_msg;


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
		if((type ==DTYPE_MESSAGE) &&
			(subtype ==SUBTYPE_CONN_SYNI))
		{
			// login message trigger
			send_msg=message_create(DTYPE_TRUSTCHAT_DEMO,SUBTYPE_LOGIN_INFO,NULL);
			if(send_msg==NULL)
				return -EINVAL;
			message_add_record(send_msg,&login_data);
			ex_module_sendmsg(sub_proc,send_msg);
			state++;
		}
		else if((type ==DTYPE_TRUSTCHAT_DEMO) &&
			(subtype ==SUBTYPE_VERIFY_RETURN))
		{
			// login data return
			ret=proc_login_return(sub_proc,recv_msg);
			if(ret!=1)
				return -EINVAL;
			if(send_msg ==NULL)
				return -EINVAL;
//			ret=proc_store_msg(recv_msg);
		        void * send_msg=proc_gen_chatmsg("Do the first chat",NULL,TRUSTMSG_NORMAL,recv_msg);
			ex_module_sendmsg(sub_proc,send_msg);
			state++;
		}			
		else if((type ==DTYPE_TRUSTCHAT_DEMO) &&
			(subtype==SUBTYPE_CHAT_MSG))
		{
			//receive chat msg

			ret=proc_process_chatmsg(sub_proc,recv_msg);
			
//			if(ret>=0)
//				ret=proc_store_msg(recv_msg);

			if(state==2)
			{
		        	void * send_msg=proc_gen_chatmsg("Do the second chat","xiyang",TRUSTMSG_CRYPT,recv_msg);
				if(send_msg ==NULL)
					return -EINVAL;
//				ret=proc_store_msg(recv_msg);
				ex_module_sendmsg(sub_proc,send_msg);
				state++;
			}
			else if(state==3)
			{
				void * send_msg=proc_gen_chatmsg("Do the third  chat","xiyang",TRUSTMSG_SIGN,recv_msg);
				if(send_msg ==NULL)
					return -EINVAL;
//				ret=proc_store_msg(recv_msg);
				ex_module_sendmsg(sub_proc,send_msg);
				state++;
			}
			
		}			
	
	}

	return 0;
};

int proc_login_return(void * sub_proc,void * message)
{
	int type;
	int subtype;
	int ret;
	printf("begin proc msg_test's login return \n");

	type=message_get_type(message);
	if(type!=DTYPE_TRUSTCHAT_DEMO)
		return -EINVAL;
	subtype=message_get_subtype(message);
	if(subtype!=SUBTYPE_VERIFY_RETURN)
		return -EINVAL;

	struct verify_return * return_data;

	ret=message_get_record(message,&return_data,0);
	if(ret<0)
		return ret;
	printf("%s\n",return_data->ret_data);
	return return_data->retval;	
}


void * proc_gen_chatmsg(char * msg_str,char * receiver,int flags,void * recv_msg)
{
	char local_uuid[DIGEST_SIZE];
	char proc_name[DIGEST_SIZE];
	char user[DIGEST_SIZE];
	struct chat_msg test_msg;		
	struct msg_info * expand_info;
	int ret;

	expand_info=Talloc0(sizeof(*expand_info));
	if(expand_info==NULL)
		return -ENOMEM;

	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);
	ret=proc_share_data_getvalue("user_name",expand_info->sender);

	Memcpy(test_msg.msg_head,"TRUSTMSG",8);
	test_msg.msg=msg_str;
	test_msg.msg_size=Strlen(test_msg.msg)+1;

	get_random_uuid(expand_info->uuid);
	if(receiver!=NULL)
		Strncpy(expand_info->receiver,receiver,DIGEST_SIZE);		
        expand_info->flags=flags;	

	void * send_msg=message_create(DTYPE_TRUSTCHAT_DEMO,SUBTYPE_CHAT_MSG,NULL);
	if(send_msg==NULL)
		return -EINVAL;
		
	message_add_record(send_msg,&test_msg);
	message_add_expand_data(send_msg,DTYPE_TRUSTCHAT_EXPAND,SUBTYPE_EXPAND_INFO,expand_info);

	return send_msg;
}

int  proc_store_msg(void * recv_msg)
{
	char local_uuid[DIGEST_SIZE];
	char proc_name[DIGEST_SIZE];
	char user[DIGEST_SIZE];
	struct chat_msg * chat_msg;		
	struct msg_info * expand_info;
	struct store_msg * store_message;
	DB_RECORD * db_record;
	MSG_EXPAND * msg_expand;
	
	int ret;

	expand_info=Talloc0(sizeof(*expand_info));
	if(expand_info==NULL)
		return -ENOMEM;

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

	db_record=memdb_find(expand_info->uuid,DTYPE_TRUSTCHAT_STORE,SUBTYPE_STORE_MSG);
	if(db_record==NULL)
	// first message store
	{
		store_message=Talloc0(sizeof(*store_message));
		store_message->info=expand_info;
		store_message->msg=chat_msg;
		if(Strncmp(user,expand_info->sender,DIGEST_SIZE)==0)
		{
			store_message->store_flags=CHAT_MSG_SELF;
		}
		else
		{
			store_message->store_flags=CHAT_MSG_RECV;
		}
				
		memdb_store(store_message,DTYPE_TRUSTCHAT_STORE,SUBTYPE_STORE_MSG,NULL);

	}
	else
	{
	
	}

	return 1;
}

int proc_process_chatmsg(void * sub_proc,void * recv_msg)
{
	struct chat_msg * chat_msg;		
	struct msg_info * expand_info;
	struct store_msg * store_message;
	DB_RECORD * db_record;
	MSG_EXPAND * msg_expand;
	int ret;

	ret=message_get_record(recv_msg,&chat_msg,0);
	if(ret<0)
		return ret;
	
	ret=message_get_define_expand(recv_msg,&msg_expand,DTYPE_TRUSTCHAT_EXPAND,SUBTYPE_EXPAND_INFO);	
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
		return -EINVAL;
	expand_info=msg_expand->expand;
	
	printf("sender: %s   receiver: %s\n",expand_info->sender,expand_info->receiver);
	printf("msg: %s\n", chat_msg->msg);

	return 0;
	
}
	
/*
int proc_verify(void * sub_proc,void * message)
{
	int type;
	int subtype;
	int ret;
	printf("begin proc msg_test \n");

	type=message_get_type(message);
	if(type!=DTYPE_TRUSTCHAT_DEMO)
		return -EINVAL;
	subtype=message_get_subtype(message);
	if(subtype!=SUBTYPE_LOGIN_INFO)
		return -EINVAL;

	void * new_msg;
	void * record;
	
	struct login_info * login_data;
	struct login_info * lib_data;
	struct verify_return * return_data;

	new_msg=message_create(DTYPE_TRUSTCHAT_DEMO,SUBTYPE_VERIFY_RETURN,message);
	return_data=Talloc0(sizeof(*return_data));

	ret=message_get_record(message,&login_data,0);
	if(ret<0)
		return ret;

	lib_data=memdb_get_first_record(type,subtype);
	while(lib_data!=NULL)
	{
		if(Strncmp(lib_data->user,login_data->user,DIGEST_SIZE)==0)
			break;
		lib_data=memdb_get_next_record(type,subtype);
	}
	if(lib_data==NULL)
	{
		return_data->ret_data=dup_str("no such user!",0);
		return_data->retval=-1;
	}
	else
	{
		if (Strncmp(lib_data->passwd,login_data->passwd,DIGEST_SIZE)!=0)
		{
			return_data->ret_data=dup_str("error passwd!",0);
			return_data->retval=0;
		}
		else
		{
			return_data->ret_data=dup_str("login_succeed!",0);
			return_data->retval=1;
			ret=user_addr_store(sub_proc,message);
			if(ret<0)
				return ret;
		}
	}
	return_data->ret_data_size=Strlen(return_data->ret_data)+1;
	message_add_record(new_msg,return_data);
	ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

int user_addr_store(void * sub_proc,void * message)
{
	
	int ret;
	struct user_address * user_addr;
	MSG_EXPAND * expand;
	struct expand_flow_trace * flow_trace;
	struct login_info * login_data;
	DB_RECORD * db_record;
	int trace_offset;
	
	ret=message_get_record(message,&login_data,0);
	if(ret<0)
		return ret;
	ret=message_get_define_expand(message,&expand,DTYPE_MSG_EXPAND,SUBTYPE_FLOW_TRACE);
	if(ret<0)
		return ret;
	if(expand==NULL)
		return -EINVAL;
	flow_trace=expand->expand;

	if(flow_trace->record_num<=0)
		return -EINVAL;
	trace_offset=DIGEST_SIZE*(flow_trace->record_num-1);
	db_record=memdb_find_byname(login_data->user,DTYPE_TRUSTCHAT_STORE,SUBTYPE_STORE_USERADDR);
	if(db_record!=NULL)
	{
		user_addr=(struct user_address *)db_record->record;
		if(Memcmp(user_addr->addr,flow_trace->trace_record+trace_offset,DIGEST_SIZE)==0)
			return 0;	
		memdb_remove_record(db_record);
	}
	user_addr=Talloc0(sizeof(struct user_address));
	if(user_addr==NULL)
		return -ENOMEM;
	Strncpy(user_addr->user,login_data->user,DIGEST_SIZE);
	Memcpy(user_addr->addr,flow_trace->trace_record+trace_offset,DIGEST_SIZE);
	memdb_store(user_addr,DTYPE_TRUSTCHAT_STORE,SUBTYPE_STORE_USERADDR,login_data->user);
	return 1;
}
*/
