#ifndef __PINGVPN_PUBLIC_H__
#define __PINGVPN_PUBLIC_H__

#define PINGVPN_SOCK_OPTVAL 5555

enum{
	PINGVPN_OPT_NONE,
	PINGVPN_OPT_CONF,
	PINGVPN_OPT_DEBUG,
	PINGVPN_OPT_INFO,
	PINGVPN_OPT_LIST,
};

enum{
	OPT_RET_OK=0,
	OPT_RET_NOT,
	OPT_RET_NO_MEM,
	OPT_RET_EXIST,
	OPT_RET_NO_EXIST,
	OPT_RET_TYPE_ERROR,
};

enum{
	MODE_NONE,
	MODE_SERVER,
	MODE_CLIENT,
};

struct pingvpn_opt{
	__u32 opt;
	__u32 len;
	int ret;
	__u8 data[0];
};

struct pingvpn_opt_list{
	int num;
	__u8 data[0];
};

struct pingvpn_opt_conf{
	__u8 set;
	__u8 mode;
	__u8 debug;
	__u8 alive;
	__u32 daddr;
};

struct pingvpn_opt_ct{
	__u32 client_ip;
	__u32 src_ip;
	__u32 dest_ip;
	__u16 src_port;
	__u16 dest_port;
	__u16 proto;
	__u16 pad;
};

struct pingvpn_info{
	__u64 rxPackages;
	__u64 txPackages;
	__u64 rxBytes;
	__u64 txBytes;
	__u32 rxSpeed;
	__u32 txSpeed;
};


#endif


