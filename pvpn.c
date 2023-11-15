#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h> 
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

typedef unsigned long long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

#include "comm.h"

#define streq(s1,s2) (!strcmp(s1, s2))


static inline char *ipstr(__u32 ip)
{
	static char str[20]={0};
	unsigned char *ip_dot=(unsigned char *)&ip;

	sprintf(str,"%d.%d.%d.%d",ip_dot[0],ip_dot[1],ip_dot[2],ip_dot[3]);
	return str;
}


char *mode_str(__u8 mode)
{
	switch(mode){
		case MODE_SERVER:
			return "server";
		case MODE_CLIENT:
			return "client";
		default:
			return "none";
	}
}

static inline char *opt_ret_str(int ret)
{
	int i;
	static const struct {
		int ret;
		char *str;
	}retStr[]={
		{OPT_RET_OK,"ok"},
		{OPT_RET_NOT,"NOT"},
		{OPT_RET_NO_MEM,"NO_MEM"},
		{OPT_RET_EXIST,"EXIST"},
		{OPT_RET_NO_EXIST,"NO_EXIST"},
		{OPT_RET_TYPE_ERROR,"TYPE_ERROR"},
		{0,NULL}
	};
	
	for(i=0;retStr[i].str;i++){
		if(ret==retStr[i].ret){
			return retStr[i].str;
		}
	}
	return "unknown";
}


char *transByte(unsigned long long byte)
{
	unsigned long long tmp;
	int Gbyte=0,Mbyte=0,Kbyte=0,Byte=0;
	static char str[64]={0};
	int len=0;

	if(byte>1023){
		tmp=byte;
		Byte=tmp%1024;
		Kbyte=(tmp-Byte)/1024;
		if(Kbyte>1023){
			tmp=Kbyte;
			Kbyte=tmp%1024;
			Mbyte=(tmp-Kbyte)/1024;
			if(Mbyte>1023){
				tmp=Mbyte;
				Mbyte=tmp%1024;
				Gbyte=(tmp-Mbyte)/1024;
			}
		}
	}else{
		Byte=(typeof(Byte))byte;
	}
	if(Gbyte){
		len+=snprintf(str+len, sizeof(str)-len, "%d.%02d G", Gbyte, Mbyte/10>99?99:Mbyte/10);
		return str;
	}
	if(Mbyte){
		len+=snprintf(str+len, sizeof(str)-len, "%d.%02d M", Mbyte, Kbyte/10>99?99:Kbyte/10);
		return str;
	}
	if(Kbyte){
		len+=snprintf(str+len, sizeof(str)-len, "%d.%02d K", Kbyte, Byte/10>99?99:Byte/10);
		return str;
	}

	len+=snprintf(str+len, sizeof(str)-len, "%d B", Byte);
	return str;
}

char *proto_str(__u8 proto)
{
	switch(proto){
		case IPPROTO_TCP:
			return "TCP";
		case IPPROTO_UDP:
			return "UDP";
		case IPPROTO_ICMP:
			return "ICMP";
		default:
			return "Unknown";
	}
}




__u32 StrToIp(char * stringin )
{
	char * cp;
	int dots = 0;
	int number;
	union{
   		unsigned char c[4];
   		__u32 l;
   	} retval;
	if(!stringin)
		return 0;
	
   	cp = stringin;
   	while(*cp)
   	{
    	if(*cp > '9' || *cp < '.' || *cp == '/')
        	return 0;
      	if(*cp == '.')	dots++;
      	cp++;
   	}

   	if( dots != 3 )
    	return 0;

   	cp = stringin;
   	if((number = atoi(cp)) > 255)
    		return 0;
	if(number==0)
		return 0;
	
   	retval.c[0] = (unsigned char)number;

   	while(*cp != '.')cp++;
   	cp++;
	
    	number = atoi(cp);
      	while(*cp != '.')cp++;
      	cp++;
      	if(number > 255) return 0;
      	retval.c[1] = (unsigned char)number;
   	
  
      number = atoi(cp);
      while(*cp != '.')cp++;
      cp++;
      if(number > 255) return 0;
      retval.c[2] = (unsigned char)number;
  
   if((number = atoi(cp)) >255)
      return 0;
   retval.c[3] = (unsigned char)number;

   return (retval.l);
}

int get_opt(void *buf, int len)
{
    int max_rev, sockfd;
    int ret = 0;
    sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0)
    {
        fprintf (stderr, "Could not open socket to kernel: %s\n", strerror (errno) );
        ret = -1;
        return ret;
    }

    max_rev = getsockopt (sockfd, IPPROTO_IP, PINGVPN_SOCK_OPTVAL, buf, (socklen_t *)&len);
    if (max_rev < 0)
    {
        fprintf (stderr, "getsockopt failed: %s\n",strerror (errno));
        ret = -2;
    }
    close (sockfd);
    return ret;

}


int ptopt_debug(int argc, char **argv)
{
	char buf[1024]={0};
	struct pingvpn_opt *opt=(typeof(opt))buf;
	struct pingvpn_opt_conf *conf=(typeof(conf))opt->data;

	if(argc<3){
		goto help;
	}
	
	opt->opt=PINGVPN_OPT_DEBUG;
	if(streq(argv[2], "1")){
		conf->debug=1;
	}else if(streq(argv[2], "0")){
		conf->debug=0;
	}else{
		goto help;
	}
	opt->len=sizeof(*opt)+sizeof(*conf);

	if(get_opt(opt,opt->len)){
		printf("get_opt error\n");
		return -1;
	}
	if(opt->ret!=OPT_RET_OK){
		printf("opt->ret:%s error\n",opt_ret_str(opt->ret));
		return -1;
	}

	printf("ok\n");
	
	return 0;
	
help:
	printf("Usage: %s debug [0/1]\n",argv[0]);
	return -1;
}


int ptopt_info(int argc, char **argv)
{
	char buf[1024]={0};
	struct pingvpn_opt *opt=(typeof(opt))buf;
	struct pingvpn_info *info=(typeof(info))opt->data;

	opt->opt=PINGVPN_OPT_INFO;
	opt->len=sizeof(*opt)+sizeof(*info);

	if(get_opt(opt,opt->len)){
		printf("get_opt error\n");
		return -1;
	}
	if(opt->ret!=OPT_RET_OK){
		printf("opt->ret:%s error\n",opt_ret_str(opt->ret));
		return -1;
	}

	printf("rxPackages:%llu\n",info->rxPackages);
	printf("txPackages:%llu\n",info->txPackages);
	printf("rxBytes:%s\n",transByte(info->rxBytes));
	printf("txBytes:%s\n",transByte(info->txBytes));
	printf("rxSpeed:%s/S\n",transByte(info->rxSpeed));
	printf("txSpeed:%s/S\n",transByte(info->txSpeed));

	return 0;
}

int ptopt_conf(int argc, char **argv)
{
	char buf[1024]={0};
	struct pingvpn_opt *opt=(typeof(opt))buf;
	struct pingvpn_opt_conf *conf=(typeof(conf))opt->data;
	

	opt->opt=PINGVPN_OPT_CONF;
	opt->len=sizeof(*opt)+sizeof(*conf);
	if(argc<3){
		conf->set=0;
	}else if(streq(argv[2], "server")){
		conf->set=1;
		conf->mode=MODE_SERVER;
	}else if(streq(argv[2], "client")){
		conf->set=1;
		conf->mode=MODE_CLIENT;
		if(argc<5){
			goto help;
		}
		conf->daddr=StrToIp(argv[3]);
		if(!conf->daddr){
			goto help;
		}
		conf->alive=(__u8)atoi(argv[4]);
	}else{
		conf->set=0;
	}

	if(get_opt(opt,opt->len)){
		printf("get_opt error\n");
		return -1;
	}
	if(opt->ret!=OPT_RET_OK){
		printf("opt->ret:%s error\n",opt_ret_str(opt->ret));
		return -1;
	}
	
	if(conf->set){
		printf("ok\n");
	}else{
		printf("mode:%s\n",mode_str(conf->mode));
		printf("debug:%d\n",conf->debug);
		if(conf->mode==MODE_CLIENT){
			printf("server_ip:%s\n",ipstr(conf->daddr));
			printf("alive:%d\n",conf->alive);
		}
	}
	
	return 0;
help:
	printf("Usage: %s conf [server/client] server_ip alive\n",argv[0]);
	return -1;
}


int ptopt_list(int argc, char **argv)
{
	int i;
	char buf[10240]={0};
	struct pingvpn_opt *opt=(typeof(opt))buf;
	struct pingvpn_opt_list *list;
	struct pingvpn_opt_ct *ct;

	opt->opt=PINGVPN_OPT_LIST;
	opt->len=sizeof(buf);

	if(get_opt(opt,opt->len)){
		printf("get_opt error\n");
		return -1;
	}
	if(opt->ret!=OPT_RET_OK){
		printf("opt->ret:%s error\n",opt_ret_str(opt->ret));
		return -1;
	}

	list=(typeof(list))opt->data;
	ct=(typeof(ct))list->data;
	
	for(i=0;i<list->num;i++){
		printf("%-2d client_ip:%s ",i+1,ipstr(ct->client_ip));
		printf("src_ip:%s ",ipstr(ct->src_ip));
		printf("dest_ip:%s ",ipstr(ct->dest_ip));
		printf("src_port:%d ",ntohs(ct->src_port));
		printf("dest_port:%d ",ntohs(ct->dest_port));
		printf("proto:%s \n",proto_str(ct->proto));
		ct++;
	}

	return 0;
}

int main(int argc, char **argv)
{
	if(argc<2){
		goto help;
	}

	if(streq(argv[1], "conf")){
		return ptopt_conf(argc, argv);
	}else if(streq(argv[1], "debug")){
		return ptopt_debug(argc, argv);
	}else if(streq(argv[1], "info")){
		return ptopt_info(argc, argv);
	}else if(streq(argv[1], "list")){
		return ptopt_list(argc, argv);
	}else{
		goto help;
	}

	return 0;
help:
	printf("Usage: %s [options] [args]\n",argv[0]);
	printf("options:\n");
	printf("\t[conf/debug/info/list]\n");
	return -1;
}

