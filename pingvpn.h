#ifndef __PINGVPN_H__
#define __PINGVPN_H__

#include <linux/fs.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/poll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/vmalloc.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/timer.h>
#include <linux/kmod.h>
#include <linux/input.h>
#include <linux/inetdevice.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/ip.h>

#include "pingvpn_public.h"

#define PINGVPN_HEAD_SIZE 32	//iph(20)+icmph(8)+pth(4)
#define SKB_MAX_HEAD_LEN 56	//eth(14+2)+iph(20)+icmph(8)+ppph(8)+pth(4)
#define SKB_MAX_LEN 1520
#define PINGVPN_MAGIC 0x1A3B5C7D
#define PINGVPN_MAX_MTU 1468

#define Printk(format,args...) do{if(pingvpn.debug)printk("[%s:%d]:"format,__FUNCTION__,__LINE__,##args);}while(0)

#define PINGVPN_CONNTRACK_TIMEOUT (600*HZ)

/*
	确定一条连接的5元组
*/
struct pingvpn_tuple
{
	__be32 src_ip;		//大端序
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__be16 proto;
	__be16 pad;
};

struct pingvpn_conntrack{
	struct rcu_head rcu;
	struct list_head list;
	struct timer_list timer;
	struct pingvpn_tuple tuple;
	struct nf_conn *nfct;	//ICMP的
	spinlock_t lock;	//lock nfct
	__u32 daddr;
	__u16 iph_id;
	__u16 icmp_id;
	__u16 icmp_seq;
};

struct pthdr{
	__be32 magic;
};

struct pingvpn_dev_priv{
	struct net_device *dev;
};


struct pingvpn_var{
	struct list_head conntracks;
	struct timer_list rxTimer;
	struct timer_list txTimer;
	struct timer_list aliveTimer;
	struct timer_list enableTimer;
	struct pingvpn_dev_priv *dev_priv;
	struct nf_conn *nfct;
	spinlock_t nfct_lock;
	spinlock_t ct_lock;
	
	__u8 mode;
	__u8 debug;
	__u8 alive;
	__u8 enable;
	
	__u32 daddr;	//对端IP
	__u16 iph_id;
	__u16 icmp_id;
	__u16 icmp_seq;
	
	__u32 random;
	
	__u64 rxPackages;
	__u64 txPackages;
	__u64 rxBytes;
	__u64 txBytes;
	__u32 rxHzByte;
	__u32 txHzByte;
	__u32 rxSpeed;
	__u32 txSpeed;
};


static inline char *ipproto_str(__u8 proto)
{
	switch(proto){
		case IPPROTO_TCP:
			return "TCP";
		case IPPROTO_UDP:
			return "UDP";
		case IPPROTO_ICMP:
			return "ICMP";
		default:
			return "Unknow";
	}
}

static inline char *icmptype_str(__u8 type)
{
	switch(type){
		case ICMP_ECHO:
			return "ECHO";
		case ICMP_ECHOREPLY:
			return "ECHOREPLY";
		case ICMP_DEST_UNREACH:
			return "DEST_UNREACH";
		case ICMP_REDIRECT:
			return "REDIRECT";
		default:
			return "Unknow";
	}
}


static inline void __print_skb_ip(struct sk_buff *skb,char *fun,int line)
{
	struct iphdr *iph=ip_hdr(skb);

	if(likely(iph)){
		//if(net_ratelimit()){
			printk("[%s:%d]: len:%d saddr:%pI4 daddr:%pI4 protocol:%s tlen:%d ",fun,line,skb->len,&iph->saddr,&iph->daddr,ipproto_str(iph->protocol),ntohs(iph->tot_len));
			if(iph->protocol==IPPROTO_TCP){
				struct tcphdr *tcph=(void *)iph+iph->ihl*4;
				printk("sport:%d dport:%d syn:%d ack:%d rst:%d\n",ntohs(tcph->source),ntohs(tcph->dest),tcph->syn,tcph->ack,tcph->rst);
			}else if(iph->protocol==IPPROTO_UDP){
				struct udphdr *udph=(void *)iph+iph->ihl*4;
				printk("sport:%d dport:%d\n",ntohs(udph->source),ntohs(udph->dest));
			}else{
				struct icmphdr *icmph=(void *)iph+iph->ihl*4;
				printk("type:%s code:%d id:%d seq:%d\n",icmptype_str(icmph->type), icmph->code, ntohs(icmph->un.echo.id),ntohs(icmph->un.echo.sequence));
			}
		//}
	}
}
#define print_skb_ip(skb) do{if(pingvpn.debug)__print_skb_ip(skb, (char *)__FUNCTION__, __LINE__);}while(0)

#endif

