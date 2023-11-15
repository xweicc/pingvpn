
#include "pingvpn.h"

struct pingvpn_var pingvpn;

void pingvpn_get_tuple(struct iphdr *iph, struct pingvpn_tuple *tuple)
{
	tuple->proto=iph->protocol;
	tuple->src_ip=iph->saddr;
	tuple->dest_ip=iph->daddr;
	if(iph->protocol==IPPROTO_TCP){
		struct tcphdr *tcph=(void *)iph+iph->ihl*4;
		tuple->src_port=tcph->source;
		tuple->dest_port=tcph->dest;
	}else if(iph->protocol==IPPROTO_UDP){
		struct udphdr *udph=(void *)iph+iph->ihl*4;
		tuple->src_port=udph->source;
		tuple->dest_port=udph->dest;
	}else{
		tuple->src_port=0;
		tuple->dest_port=0;
	}
}

void printHex(void *data, int len)
{
	__u8 *p=data;
	int i,slen=0;
	char *buf;
	if(!pingvpn.debug){
		return ;
	}
	buf=kmalloc(len*4,GFP_ATOMIC);
	if(!buf){
		return ;
	}
	for(i=0;i<len;i++){
		slen+=sprintf(buf+slen,"%02X ",p[i]);
	}
	slen+=sprintf(buf+slen,"\n");
	printk(buf);
	kfree(buf);
}


static inline void pingvpn_srandom(__u32 *seed,__u32  ubound)
{
	__u32 random_seed = (ubound & 0x7fffffffu);
	if (random_seed == 0 || random_seed == 2147483647L) {
      random_seed = 1;
    }
	*seed = random_seed;
}

static inline __u32 pingvpn_random(__u32 *seed)
{
	static const __u32 M = 2147483647L;
	static const __u64 A = 16807;
	__u64 product = (*seed) * A;

	*seed = (__u32)((product >> 31) + (product & M));
	if(*seed > M){
		*seed -= M;
	}
	return *seed;
}



struct pingvpn_conntrack *pingvpn_conntrack_find_tuple(struct pingvpn_tuple *tuple)
{
	struct pingvpn_conntrack *ct=NULL;

	list_for_each_entry_rcu(ct, &pingvpn.conntracks, list){
		if(tuple->src_ip==ct->tuple.src_ip && tuple->dest_ip==ct->tuple.dest_ip && tuple->src_port==ct->tuple.src_port && tuple->dest_port==ct->tuple.dest_port && tuple->proto==ct->tuple.proto){
			return ct;
		}
	}

	return NULL;
}

struct pingvpn_conntrack *pingvpn_conntrack_find_tuple_reply(struct pingvpn_tuple *tuple)
{
	struct pingvpn_conntrack *ct=NULL;

	list_for_each_entry_rcu(ct, &pingvpn.conntracks, list){
		if(tuple->src_ip==ct->tuple.dest_ip && tuple->dest_ip==ct->tuple.src_ip && tuple->src_port==ct->tuple.dest_port && tuple->dest_port==ct->tuple.src_port && tuple->proto==ct->tuple.proto){
			return ct;
		}
	}

	return NULL;
}


void pingvpn_conntrack_rcu_free(struct rcu_head *head)
{
	struct pingvpn_conntrack *ct = container_of(head, struct pingvpn_conntrack, rcu);
	kfree(ct);
}


void pingvpn_nfct_unbind(struct pingvpn_conntrack *ct, struct nf_conn *old)
{
	struct nf_conn *nfct=NULL;
	if(ct){
		spin_lock_bh(&ct->lock);
		if(ct->nfct==old){
			nfct=ct->nfct;
			ct->nfct=NULL;
		}
		spin_unlock_bh(&ct->lock);
	}else{
		spin_lock_bh(&pingvpn.nfct_lock);
		if(pingvpn.nfct==old){
			nfct=pingvpn.nfct;
			pingvpn.nfct=NULL;
		}
		spin_unlock_bh(&pingvpn.nfct_lock);
	}

	if(nfct){
		nf_conntrack_put(&nfct->ct_general);
	}
}

void __print_tuple(struct pingvpn_tuple *tuple,char *fun,int line)
{
	if(net_ratelimit()){
		printk("[%s:%d]: tuple saddr:%pI4 daddr:%pI4 sport:%d dport:%d protocol:%s \n",fun,line
			,&tuple->src_ip,&tuple->dest_ip,ntohs(tuple->src_port),ntohs(tuple->dest_port),ipproto_str(tuple->proto));
	}
}

#define print_tuple(tuple) do{if(pingvpn.debug)__print_tuple(tuple, (char *)__FUNCTION__, __LINE__);}while(0)


void pingvpn_conntrack_timeout(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
struct timer_list *t
#else
unsigned long data
#endif
)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	struct pingvpn_conntrack *ct=from_timer(ct, t, timer);
#else
	struct pingvpn_conntrack *ct=(typeof(ct))data;
#endif

	print_tuple(&ct->tuple);
	spin_lock_bh(&pingvpn.ct_lock);
	list_del_rcu(&ct->list);
	spin_unlock_bh(&pingvpn.ct_lock);
	if(ct->nfct){
		pingvpn_nfct_unbind(ct, ct->nfct);
	}
	call_rcu(&ct->rcu, pingvpn_conntrack_rcu_free);
}

struct pingvpn_conntrack *pingvpn_conntrack_create(struct pingvpn_tuple *tuple)
{
	struct pingvpn_conntrack *ct=kmalloc(sizeof(*ct), GFP_ATOMIC);
	if(!ct){
		Printk("kmalloc failed\n");
		return NULL;
	}
	memset(ct,0,sizeof(*ct));

	memcpy(&ct->tuple, tuple, sizeof(*tuple));

	print_tuple(tuple);
	ct->iph_id=(__u16)pingvpn_random(&pingvpn.random);
	spin_lock_init(&ct->lock);

	spin_lock_bh(&pingvpn.ct_lock);
	list_add_rcu(&ct->list, &pingvpn.conntracks);
	spin_unlock_bh(&pingvpn.ct_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	timer_setup(&ct->timer, pingvpn_conntrack_timeout, 0);
#else
	setup_timer(&ct->timer, pingvpn_conntrack_timeout, (unsigned long)ct);
#endif
	mod_timer(&ct->timer, jiffies+PINGVPN_CONNTRACK_TIMEOUT);
	
	return ct;
}


struct pingvpn_conntrack *pingvpn_conntrack_find_create(struct iphdr *iph)
{
	struct pingvpn_tuple tuple={0};
	struct pingvpn_conntrack *ct;
	
	pingvpn_get_tuple(iph, &tuple);

	print_tuple(&tuple);
	ct=pingvpn_conntrack_find_tuple(&tuple);
	if(ct){
		mod_timer(&ct->timer, jiffies+PINGVPN_CONNTRACK_TIMEOUT);
		return ct;
	}

	return pingvpn_conntrack_create(&tuple);
}

void pingvpn_conntrack_list_free(void)
{
	struct pingvpn_conntrack *pos, *n;
	
	list_for_each_entry_safe(pos, n, &pingvpn.conntracks, list){
		list_del_rcu(&pos->list);
		del_timer_sync(&pos->timer);
		if(pos->nfct){
			pingvpn_nfct_unbind(pos, pos->nfct);
		}
		call_rcu(&pos->rcu, pingvpn_conntrack_rcu_free);
	}
}


static inline int pingvpn_ip_route_output_key(struct rtable **rt, struct flowi *flp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,0,0)
	*rt = ip_route_output_key(&init_net, (struct flowi4 *)&(flp->u.ip4));
	if (IS_ERR(*rt))
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21)
	if (ip_route_output_key(&init_net, rt, flp) < 0)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,7)
	if (ip_route_output_key(rt, flp) < 0) 
#endif
		return -1;
	else
		return 0;
}

static inline int pingvpn_skb_output(struct rtable *rt, struct sk_buff *skb)
{
	pingvpn.txPackages++;
	pingvpn.txHzByte+=skb->len;
	pingvpn.txBytes+=skb->len;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	return rt->u.dst.output(skb);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3,10,0)
	return rt->dst.output(NULL,skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	return rt->dst.output(&init_net,NULL,skb);
#else
	return rt->dst.output(skb);
#endif
}


static inline void iphdr_set_check(struct iphdr *iph)
{
	iph->check=0;
	iph->check=ip_fast_csum((unsigned char *)iph, iph->ihl);

	if(iph->protocol==IPPROTO_TCP){
		struct tcphdr *tcph=(void *)iph+iph->ihl*4;
		int tcplen=ntohs(iph->tot_len)-sizeof(*iph);
		tcph->check=0;
		tcph->check=csum_tcpudp_magic(iph->saddr,iph->daddr,tcplen, IPPROTO_TCP,csum_partial((__u8 *)tcph, tcplen, 0));
	}else if(iph->protocol==IPPROTO_UDP){
		struct udphdr *udph=(void *)iph+iph->ihl*4;
		int udplen=ntohs(iph->tot_len)-sizeof(*iph);
		udph->check=0;
		udph->check=csum_tcpudp_magic(iph->saddr,iph->daddr,udplen, IPPROTO_UDP,csum_partial((__u8 *)udph, udplen, 0));
	}
}

static inline void iphdr_set_saddr(struct iphdr *iph, __u32 saddr)
{
	iph->saddr=saddr;
	iphdr_set_check(iph);
}

static inline void iphdr_set_daddr(struct iphdr *iph, __u32 daddr)
{
	iph->daddr=daddr;
	iphdr_set_check(iph);
}

int pingvpn_skb_set_nfct(struct sk_buff *skb, struct pingvpn_conntrack *ct)
{
	struct nf_conn *nfct;

	if(ct){
		nfct=rcu_dereference(ct->nfct);
		if(!nfct){
			//Printk("nfct is null!\n");
			return -1;
		}
	}else{
		nfct=rcu_dereference(pingvpn.nfct);
		if(!nfct){
			return -1;
		}
	}

	nf_conntrack_get(&nfct->ct_general);
	if(nf_ct_is_dying(nfct)){
		pingvpn_nfct_unbind(ct, nfct);
		nf_conntrack_put(&nfct->ct_general);
		Printk("nf_ct_is_dying!\n");
		return -1;
	}
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	if(pingvpn.mode==MODE_CLIENT){
		nf_ct_set(skb, nfct, IP_CT_ESTABLISHED);
	}else{
		nf_ct_set(skb, nfct, IP_CT_ESTABLISHED+IP_CT_IS_REPLY);
	}
#else
	skb->nfct = &nfct->ct_general;
	if(pingvpn.mode==MODE_CLIENT){
		skb->nfctinfo = IP_CT_ESTABLISHED;
	}else{
		skb->nfctinfo = IP_CT_ESTABLISHED+IP_CT_IS_REPLY;
	}
#endif

	return 0;
}


/*
	返回 0:发送成功,其他:失败,需要释放skb
	调用时skb->data指向封装头的IP头
*/
int pingvpn_skb_send(struct sk_buff *skb, __u32 daddr, struct pingvpn_conntrack *ct)
{
	struct rtable *rt;
	struct flowi fl ;
	__u32 saddr=0;

	memset(&fl, 0, sizeof(fl));
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	fl.fl4_dst=daddr;
#else
	fl.u.ip4.daddr=daddr;
#endif

	if(pingvpn_ip_route_output_key(&rt, &fl)<0){
		Printk("pingvpn_ip_route_output_key err\n");
		goto err;
	}

	//选路后再确定源IP
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	saddr = rt->rt_src;
#else
	saddr = fl.u.ip4.saddr;
#endif

	skb_dst_set(skb, (struct dst_entry *)rt);

	skb->dev = skb_dst(skb)->dev;
	skb->protocol = htons(ETH_P_IP);

	if(skb->dev==pingvpn.dev_priv->dev){
		Printk("dst dev is ptun!\n");
		goto err;
	}
	
	//继续封装IP头的源IP
	iphdr_set_saddr(ip_hdr(skb), saddr);

	if(pingvpn_skb_set_nfct(skb,ct)){
		if(!ct){
			struct nf_conn *nfct;
			enum ip_conntrack_info ctinfo;
			#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
			struct nf_hook_state state;
			nf_hook_state_init(&state, NF_INET_LOCAL_OUT, PF_INET, pingvpn.dev_priv->dev, skb->dev, NULL, dev_net(skb->dev), NULL);
			if(nf_conntrack_in(skb, &state) != NF_ACCEPT)
			#else
			if(nf_conntrack_in(dev_net(skb->dev), PF_INET, NF_INET_LOCAL_OUT, skb) != NF_ACCEPT)
			#endif
			{
				Printk("nf_conntrack_in err!\n");
				goto err;
			}
			nfct=nf_ct_get(skb, &ctinfo);
			if(!nfct){
				Printk("nf_ct_get error\n");
				goto err;
			}
			spin_lock_bh(&pingvpn.nfct_lock);
			if(!pingvpn.nfct){
				pingvpn.nfct=nfct;
				nf_conntrack_get(&nfct->ct_general);
				nfct=NULL;
			}
			spin_unlock_bh(&pingvpn.nfct_lock);
			if(nfct){
				nf_conntrack_put(&nfct->ct_general);
			}
		}
	}

	if(unlikely(nf_conntrack_confirm(skb) != NF_ACCEPT)){
		Printk("nf_conntrack_confirm err!\n");
		goto err;
	}

	print_skb_ip(skb);
	//发送skb
	if(pingvpn_skb_output(rt,skb)){
		Printk("output failed\n");
	}

	return 0;

err:
	return -1;
}

static u_int16_t cheat_check(u_int32_t oldvalinv, u_int32_t newval, u_int16_t oldcheck)
{
	u_int32_t diffs[] = { oldvalinv, newval };
	return csum_fold(csum_partial((__u8 *)diffs, sizeof(diffs), oldcheck^0xFFFF));
}

static inline unsigned int
optlen(const u_int8_t *opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0) return 1;
	else return opt[offset+1];
}

void  pingvpn_tcpmss_modify(struct sk_buff *skb,struct iphdr *iph,struct tcphdr *tcph,__u16 newmss)
{
	unsigned int i;
	u_int8_t *opt;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	if (!skb_try_make_writable(skb, tcph->doff*4 + iph->ihl*4))
#else
	if (!skb_make_writable(skb, tcph->doff*4 + iph->ihl*4))
#endif
	{
		return;
	}
	
 	opt = (u_int8_t *)tcph;
	for (i = sizeof(struct tcphdr); i < tcph->doff*4; i += optlen(opt, i))
	{
		if ((opt[i] == TCPOPT_MSS) &&
		    ((tcph->doff*4 - i) >= TCPOLEN_MSS) &&
		    (opt[i+1] == TCPOLEN_MSS)) 
		{
			u_int16_t oldmss;
			oldmss = (opt[i+2] << 8) | opt[i+3];

			if(oldmss <= newmss)
				return;

			opt[i+2] = (newmss & 0xff00) >> 8;
			opt[i+3] = (newmss & 0x00ff);

			tcph->check = cheat_check(htons(oldmss)^0xFFFF,
						  htons(newmss),
						  tcph->check);
		
			return;
		}
    }
}


unsigned short checksum(unsigned short *buffer, int size)
{
	unsigned long cksum=0;
	while(size >1) {
		cksum+=*buffer++;
		size-=sizeof(unsigned short);
	}
	if(size) cksum+=*(unsigned char*)buffer;
	cksum=(cksum >> 16)+(cksum&0xffff);
	cksum+=(cksum >>16);
	return (unsigned short)(~cksum);
}



static void skb_set_icmphdr(struct sk_buff *skb, int icmplen, __u16 icmp_id, __u16 icmp_seq)
{
	struct icmphdr *icmph=NULL;

	icmph=(typeof(icmph))skb_push(skb,sizeof(struct icmphdr));
	memset(icmph, 0, sizeof(struct icmphdr));
	skb_set_transport_header(skb, 0);

	icmph->code=0;
	icmph->un.echo.id=htons(icmp_id);
	icmph->un.echo.sequence=htons(icmp_seq);
	if(pingvpn.mode==MODE_CLIENT){
		icmph->type=ICMP_ECHO;
	}else{
		icmph->type=ICMP_ECHOREPLY;
	}
	icmph->checksum=0;
	icmph->checksum=checksum((void *)icmph, icmplen);
}

static void skb_set_iphdr(struct sk_buff *skb, int iplen, __u32 daddr, __u16 iph_id)
{
	struct iphdr *iph=NULL;

	iph=(struct iphdr *)skb_push(skb,sizeof(struct iphdr));
	memset(iph, 0, sizeof(struct iphdr));
	skb_set_network_header(skb, 0);
	
	iph->version=4;
	iph->ihl=5;
	iph->tos=0;
	iph->tot_len=htons(iplen);
	iph->frag_off|=IP_DF;
	iph->frag_off=htons(iph->frag_off);
	iph->ttl=128;
	iph->protocol=IPPROTO_ICMP;
	iph->daddr=daddr;
	iph->id=htons(iph_id);
}

static void skb_set_pthdr(struct sk_buff *skb)
{
	struct pthdr *p=(void *)skb_push(skb,sizeof(struct pthdr));
	p->magic=htonl(PINGVPN_MAGIC);
}


unsigned int pingvpn_netif_rx(struct sk_buff *skb)
{
	print_skb_ip(skb);
	
	pingvpn.rxPackages++;
	pingvpn.rxHzByte+=skb->len;
	pingvpn.rxBytes+=skb->len;
	
	skb->dev->stats.rx_packets++;
	skb->dev->stats.rx_bytes+=skb->len;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	skb->dev->last_rx = jiffies;
#endif

	return netif_rx(skb);
}


static int pingvpn_icmp_send(void *data, int len, struct pingvpn_conntrack *ct)
{
	struct sk_buff *skb;
	int icmplen=sizeof(struct icmphdr)+len+sizeof(struct pthdr);
	int iplen=sizeof(struct iphdr)+icmplen;
	__u32 daddr;
	__u16 iph_id, icmp_id, icmp_seq;

	if(iplen>SKB_MAX_LEN){
		Printk("iplen:%d error\n",iplen);
		return -1;
	}
	
	skb = dev_alloc_skb(SKB_MAX_LEN);
	if(skb == NULL){
		Printk("dev_alloc_skb failed\n");
		goto err;
	}
	skb_reserve(skb, SKB_MAX_LEN);

	if(ct){
		daddr=ct->daddr;
		iph_id=ct->iph_id++;
		icmp_id=ct->icmp_id;
		icmp_seq=ct->icmp_seq;
	}else{
		daddr=pingvpn.daddr;
		iph_id=pingvpn.iph_id++;
		icmp_id=pingvpn.icmp_id;
		icmp_seq=pingvpn.icmp_seq++;
	}

	memcpy(skb_push(skb,len), data, len);
	skb_set_pthdr(skb);
	skb_set_icmphdr(skb, icmplen, icmp_id, icmp_seq);
	skb_set_iphdr(skb, iplen, daddr, iph_id);
	skb_reset_network_header(skb);

	if(pingvpn_skb_send(skb, daddr, ct)){
		Printk("pingvpn_skb_send error\n");
		goto err;
	}

	return 0;

err:
	if(skb){
		kfree_skb(skb);
	}
	return -1;
}

void pingvpn_nfct_bind(struct pingvpn_conntrack *ct, struct nf_conn *nfct)
{
	if(ct->nfct!=nfct){
		struct nf_conn *old;

		spin_lock_bh(&ct->lock);
		old=ct->nfct;
		nf_conntrack_get(&old->ct_general);
		ct->nfct=nfct;
		spin_unlock_bh(&ct->lock);

		if(old){
			nf_conntrack_put(&old->ct_general);
		}
	}
}


static int pingvpn_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct iphdr *iph = ip_hdr(skb);
	struct pingvpn_conntrack *ct=NULL;

	if(!pingvpn.mode || !pingvpn.enable){
		goto out;
	}
	
	if((dev->flags&IFF_UP) != IFF_UP){
		goto out;
	}

	if(skb->protocol != htons(ETH_P_IP)){
		goto out;
	}

	if(iph->ttl <= 1){
		goto out;
	}
	ip_decrease_ttl(iph);

	if(iph->ihl!=5 || iph->version!=4){
		goto out;
	}

	if(iph->protocol==IPPROTO_TCP){
		struct tcphdr *tcph=(void *)iph+iph->ihl*4;
		if(tcph->syn){
			pingvpn_tcpmss_modify(skb,iph,tcph,dev->mtu-PINGVPN_HEAD_SIZE);
		}
	}

	print_skb_ip(skb);

	if(pingvpn.mode==MODE_CLIENT){
		if(pingvpn.alive){
			mod_timer(&pingvpn.aliveTimer, jiffies+2*HZ);
		}
	}else{
		struct pingvpn_tuple tuple={0};
		pingvpn_get_tuple(iph, &tuple);
		print_tuple(&tuple);
		ct=pingvpn_conntrack_find_tuple_reply(&tuple);
		if(!ct){
			Printk("not find ct\n");
			goto out;
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	dev->trans_start=jiffies;
#endif
	dev->stats.tx_packets++;
	dev->stats.tx_bytes+=ntohs(iph->tot_len);

	pingvpn_icmp_send(iph,ntohs(iph->tot_len),ct);

out:
	if(skb){
		kfree_skb(skb);
		skb=NULL;
	}
	return NETDEV_TX_OK;
}

static unsigned int pingvpn_dev_recv(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct icmphdr *icmph=(void *)iph+iph->ihl*4;
	__u8 *data;
	__u32 icmp_saddr=iph->saddr;//客户端IP
	struct pthdr *pth;
	struct pingvpn_conntrack *ct=NULL;
	struct nf_conn *nfct;
	enum ip_conntrack_info ctinfo;

	if(iph->protocol!=IPPROTO_ICMP){
		return NF_ACCEPT;
	}
	if(pingvpn.mode==MODE_SERVER){
		if(icmph->type!=ICMP_ECHO){
			return NF_ACCEPT;
		}
	}
	if(pingvpn.mode==MODE_CLIENT){
		if(icmph->type!=ICMP_ECHOREPLY){
			return NF_ACCEPT;
		}
	}
	
	print_skb_ip(skb);

	//合并skb分片
	if(!pskb_may_pull(skb,skb->len)){
		Printk("skb->len:%d error\n",skb->len);
		goto out;
	}
	iph = ip_hdr(skb);	//重新取IP头
	
	icmph=(void *)iph+iph->ihl*4;
	data=(void *)icmph+sizeof(*icmph);
	pth=(void *)data;
	if(pth->magic!=htonl(PINGVPN_MAGIC)){
		return NF_ACCEPT;
	}

	nfct=nf_ct_get(skb, &ctinfo);
	if(!nfct){
		Printk("nf_ct_get error\n");
		goto out;
	}
	if(nf_conntrack_confirm(skb) != NF_ACCEPT){
		Printk("nf_conntrack_confirm error\n");
		goto out;
	}

	data+=sizeof(*pth);

	//指向数据部分
	__skb_pull(skb, data-skb->data);
	skb_reset_network_header(skb);

	//用户数据IP头
	iph=(typeof(iph))data;

	if(ntohs(iph->tot_len)>skb->len){
		Printk("iph->tot_len:%d\n",ntohs(iph->tot_len));
		printHex(skb->data, skb->len);
		goto out;
	}

	if(pingvpn.mode==MODE_SERVER){
		ct=pingvpn_conntrack_find_create(iph);
		if(!ct){
			goto out;
		}
		ct->daddr=icmp_saddr;
		ct->icmp_id=ntohs(icmph->un.echo.id);
		ct->icmp_seq=ntohs(icmph->un.echo.sequence);
		//pingvpn_nfct_bind(ct,nfct);
	}

	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb->dev=pingvpn.dev_priv->dev;

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	nf_reset_ct(skb);
#else
	nf_reset(skb);
#endif
	skb_dst_drop(skb);

	pingvpn_netif_rx(skb);
	skb=NULL;
	
out:
	if(skb){
		kfree_skb(skb);
		skb=NULL;
	}
	return NF_STOLEN;
}



static unsigned int pingvpn_hook_fun(
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,0,0)
	unsigned int hooknum,struct sk_buff *skb, const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(3,10,0)
	const struct nf_hook_ops *ops,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,const struct nf_hook_state *state
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(3,14,0)
	const struct nf_hook_ops *ops,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	const struct nf_hook_ops *ops,struct sk_buff *skb,const struct nf_hook_state *state
#else
	void *priv, struct sk_buff *skb, const struct nf_hook_state *state
#endif
)
{
	if(!pingvpn.mode){
		return NF_ACCEPT;
	}

	return pingvpn_dev_recv(skb);
}

static struct nf_hook_ops pingvpn_hooks[]={
	{	//接收封装后的ICMP包
		.hook		= pingvpn_hook_fun,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
		.owner		= THIS_MODULE,
#endif
		.pf			= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK+1,
	}
};

static int nf_hook_init(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	return nf_register_hooks(pingvpn_hooks,ARRAY_SIZE(pingvpn_hooks));
	#else
	return nf_register_net_hooks(&init_net,pingvpn_hooks,ARRAY_SIZE(pingvpn_hooks));
	#endif
}

static void nf_hook_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	nf_unregister_hooks(pingvpn_hooks,ARRAY_SIZE(pingvpn_hooks));
#else
	nf_unregister_net_hooks(&init_net,pingvpn_hooks,ARRAY_SIZE(pingvpn_hooks));
#endif
}

__u32 get_dev_ip(struct net_device *dev)
{
	struct in_device *ip_ptr;
	struct in_ifaddr *ifa_list;

	ip_ptr=rcu_dereference_bh(dev->ip_ptr);
	if(!ip_ptr){
		return 0;
	}
	ifa_list=rcu_dereference_bh(ip_ptr->ifa_list);
	if(!ifa_list){
		return 0;
	}
	return ifa_list->ifa_address;
}

void keep_alive_timeout(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
struct timer_list *t
#else
unsigned long data
#endif
)
{
	static const char buf[]="12345678910";
	struct sk_buff *skb;
	int icmplen=sizeof(struct icmphdr)+sizeof(buf);
	int iplen=sizeof(struct iphdr)+icmplen;
	static __u16 iph_id, icmp_id, icmp_seq;
	struct iphdr *iph;

	if((pingvpn.dev_priv->dev->flags&IFF_UP) != IFF_UP){
		goto end;
	}
	
	if(iplen>SKB_MAX_LEN){
		goto end;
	}
	
	skb = dev_alloc_skb(SKB_MAX_LEN);
	if(skb == NULL){
		Printk("dev_alloc_skb %d failed\n",SKB_MAX_LEN);
		goto end;
	}
	skb_reserve(skb, SKB_MAX_LEN);

	if(!icmp_id){
		icmp_id=pingvpn_random(&pingvpn.random);
	}

	memcpy(skb_push(skb,sizeof(buf)), buf, sizeof(buf));
	skb_set_icmphdr(skb, icmplen, icmp_id, icmp_seq++);
	skb_set_iphdr(skb, iplen, pingvpn.daddr, iph_id++);
	iph=(struct iphdr *)skb->data;
	iph->saddr=get_dev_ip(pingvpn.dev_priv->dev);
	iph->check=0;
	iph->check=ip_fast_csum((unsigned char *)iph, iph->ihl);

	pingvpn_icmp_send(skb->data,skb->len,NULL);
	kfree_skb(skb);
	
end:
	mod_timer(&pingvpn.aliveTimer, jiffies+2*HZ);
}


int pingvpn_conf(void *data, int len)
{
	int ret=OPT_RET_OK;
	struct pingvpn_opt_conf *conf=data;

	if(conf->set){
		pingvpn.mode=conf->mode;
		pingvpn.daddr=conf->daddr;
		pingvpn.alive=conf->alive;
		
		if(pingvpn.alive){
			mod_timer(&pingvpn.aliveTimer, jiffies+2*HZ);
		}
	}else{
		conf->mode=pingvpn.mode;
		conf->daddr=pingvpn.daddr;
		conf->alive=pingvpn.alive;
		conf->debug=pingvpn.debug;
	}

	return ret;
}

int pingvpn_debug(void *data, int len)
{
	int ret=OPT_RET_OK;
	struct pingvpn_opt_conf *conf=data;

	pingvpn.debug=conf->debug;

	return ret;
}

int pingvpn_info_get(void *data, int len)
{
	int ret=OPT_RET_OK;
	struct pingvpn_info *info=data;

	info->rxPackages=pingvpn.rxPackages;
	info->txPackages=pingvpn.txPackages;
	info->rxBytes=pingvpn.rxBytes;
	info->txBytes=pingvpn.txBytes;
	info->rxSpeed=pingvpn.rxSpeed;
	info->txSpeed=pingvpn.txSpeed;

	return ret;
}


int pingvpn_list(void *data, int len)
{
	int ret=OPT_RET_OK;
	struct pingvpn_opt_list *list=data;
	struct pingvpn_opt_ct *ct=(typeof(ct))list->data;
	struct pingvpn_conntrack *pos;
	
	list->num=0;
	list_for_each_entry_rcu(pos, &pingvpn.conntracks, list){
		ct->client_ip=pos->daddr;
		ct->src_ip=pos->tuple.src_ip;
		ct->dest_ip=pos->tuple.dest_ip;
		ct->src_port=pos->tuple.src_port;
		ct->dest_port=pos->tuple.dest_port;
		ct->proto=pos->tuple.proto;
		ct++;
		list->num++;
	}
	return ret;
}


int pingvpn_opt_get(void   *user, int len)
{
	int ret;
	struct pingvpn_opt *opt=(typeof(opt))user;
	
	if(len != opt->len){
		return -EINVAL;
	}
	
	switch(opt->opt){
		case PINGVPN_OPT_CONF:
			ret = pingvpn_conf(opt->data, len-sizeof(*opt));
			break;
		case PINGVPN_OPT_DEBUG:
			ret = pingvpn_debug(opt->data, len-sizeof(*opt));
			break;
		case PINGVPN_OPT_INFO:
			ret = pingvpn_info_get(opt->data, len-sizeof(*opt));
			break;
		case PINGVPN_OPT_LIST:
			ret = pingvpn_list(opt->data, len-sizeof(*opt));
			break;
		default:
			ret = OPT_RET_NOT;
			break;
    }

	opt->ret=ret;
	
	return 0;
}

static int pingvpn_order_set_ctl(
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
struct sock *sk, int cmd, void  *user, unsigned int len
#else
struct sock *sk, int optval, sockptr_t arg, unsigned int len
#endif
)
{
	return -EPERM;
}

static int pingvpn_order_get_ctl(struct sock *sk, int cmd, void  *user, int *len)
{
	int ret=0;
	char *buf=NULL;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	buf=vmalloc(*len);
	if(!buf){
		return -ENOMEM;
	}
	if(copy_from_user(buf, user, *len)){
		ret = -ENOMEM;
		goto out;
	}
	
	switch (cmd) {
		case PINGVPN_SOCK_OPTVAL:
			ret = pingvpn_opt_get(buf,*len);
			break;
		default:
			ret = -EINVAL;
			break;
	}
	if(copy_to_user(user, buf, *len)){
		ret = -ENOMEM;
		goto out;
	}

out:
	if(buf){
		vfree(buf);
	}
	return ret;
}


static struct nf_sockopt_ops pingvpn_order_sockopts = {
	.pf		= PF_INET,
	.set_optmin	= PINGVPN_SOCK_OPTVAL,
	.set_optmax	= PINGVPN_SOCK_OPTVAL+1,
	.set		= pingvpn_order_set_ctl,
	.get_optmin	= PINGVPN_SOCK_OPTVAL,
	.get_optmax	= PINGVPN_SOCK_OPTVAL+1,
	.get		= pingvpn_order_get_ctl,
};

int pingvpn_sockopt_init(void)
{
	return nf_register_sockopt(&pingvpn_order_sockopts);
}

void pingvpn_sockopt_exit(void)
{
	nf_unregister_sockopt(&pingvpn_order_sockopts);
}

void rx_speed_timeout(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
struct timer_list *t
#else
unsigned long data
#endif
)
{
	pingvpn.rxSpeed=pingvpn.rxHzByte;
	pingvpn.rxHzByte=0;
	mod_timer(&pingvpn.rxTimer, jiffies+HZ);
}

void tx_speed_timeout(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
struct timer_list *t
#else
unsigned long data
#endif
)
{
	pingvpn.txSpeed=pingvpn.txHzByte;
	pingvpn.txHzByte=0;
	mod_timer(&pingvpn.txTimer, jiffies+HZ);
}


static struct net_device_stats *pingvpn_dev_stats(struct net_device *dev)
{
	return &dev->stats;
}

static int pingvpn_change_mtu(struct net_device *dev, int mtu)
{
	if(mtu<1000 || mtu>PINGVPN_MAX_MTU){
		return -EINVAL;
	}
	dev->mtu = mtu;
	return 0;
}

static const struct net_device_ops pingvpn_dev_ops={
	.ndo_start_xmit=pingvpn_dev_xmit,
	.ndo_get_stats=pingvpn_dev_stats,
	#if LINUX_VERSION_CODE != KERNEL_VERSION(3,10,0)
	.ndo_change_mtu=pingvpn_change_mtu,
	#endif
};

static void pingvpn_dev_setup(struct net_device *dev)
{
	dev->netdev_ops = &pingvpn_dev_ops;
	dev->type = ARPHRD_PPP;
	dev->hard_header_len = PINGVPN_HEAD_SIZE;
	dev->tx_queue_len = 0;
	dev->flags |= IFF_NOARP;
	dev->flags &= ~(IFF_BROADCAST|IFF_MULTICAST);
	dev->mtu = PINGVPN_MAX_MTU;
}


int pingvpn_dev_init(void)
{
	int ret;
	struct net_device *dev;
	struct pingvpn_dev_priv *priv;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
	dev = alloc_netdev(sizeof(*priv), "pvpn", pingvpn_dev_setup);
#else
	dev = alloc_netdev(sizeof(*priv), "pvpn", NET_NAME_UNKNOWN, pingvpn_dev_setup);
#endif
	if(!dev){
		printk("alloc_netdev failed\n");
		return -1;
	}
	priv=netdev_priv(dev);
	memset(priv,0,sizeof(*priv));
	priv->dev=dev;

	ret = register_netdev(dev);
	if(ret != 0){
		printk("register_netdev pvpn failed\n");
		goto out;
	}
	pingvpn.dev_priv=priv;
	
	return 0;

out:
	free_netdev(dev);
	return -1;
}

void pingvpn_dev_exit(void)
{
	struct net_device *dev=pingvpn.dev_priv->dev;
	pingvpn.dev_priv=NULL;
	
	unregister_netdev(dev);
	free_netdev(dev);
}

void enable_timeout(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
struct timer_list *t
#else
unsigned long data
#endif
)
{
	pingvpn.enable=0;
}


static int __init pingvpn_init(void)
{
	pingvpn.enable=1;
	INIT_LIST_HEAD(&pingvpn.conntracks);
	pingvpn_srandom(&pingvpn.random, jiffies);
	pingvpn.icmp_id=pingvpn_random(&pingvpn.random);
	spin_lock_init(&pingvpn.nfct_lock);
	spin_lock_init(&pingvpn.ct_lock);
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	timer_setup(&pingvpn.rxTimer, rx_speed_timeout, 0);
	timer_setup(&pingvpn.txTimer, tx_speed_timeout, 0);
	timer_setup(&pingvpn.aliveTimer, keep_alive_timeout, 0);
	timer_setup(&pingvpn.enableTimer, enable_timeout, 0);
#else
	setup_timer(&pingvpn.rxTimer, rx_speed_timeout, 0);
	setup_timer(&pingvpn.txTimer, tx_speed_timeout, 0);
	setup_timer(&pingvpn.aliveTimer, keep_alive_timeout, 0);
	setup_timer(&pingvpn.enableTimer, enable_timeout, 0);
#endif
	
	if(pingvpn_sockopt_init()){
		printk("pingvpn_sockopt_init failed\n");
		goto sock_err;
	}

	if(pingvpn_dev_init()){
		printk("pingvpn_dev_init failed\n");
		goto dev_err;
	}
	
	//注册nf_hook, 放在最后
	if(nf_hook_init()){
		printk("nf_hook_init failed\n");
		goto nf_err;
	}
	mod_timer(&pingvpn.rxTimer, jiffies+HZ);
	mod_timer(&pingvpn.txTimer, jiffies+HZ);
	mod_timer(&pingvpn.enableTimer, jiffies+60*60*24*HZ);
	
	printk("pingvpn_init ok v1.20\n");
	return 0;

nf_err:
	pingvpn_dev_exit();
dev_err:
	pingvpn_sockopt_exit();
sock_err:
	printk("pingvpn_init failed\n");
	return -1;
}


static void __exit pingvpn_exit(void)
{
	//注销nf_hook, 放在最前面
	nf_hook_exit();
	del_timer_sync(&pingvpn.aliveTimer);
	del_timer_sync(&pingvpn.rxTimer);
	del_timer_sync(&pingvpn.txTimer);
	del_timer_sync(&pingvpn.enableTimer);
	pingvpn_nfct_unbind(NULL, pingvpn.nfct);

	synchronize_net();
	rcu_barrier();

	pingvpn_conntrack_list_free();

	pingvpn_dev_exit();
	pingvpn_sockopt_exit();

	synchronize_net();
	rcu_barrier();
	printk("pingvpn_exit ok\n");
}


module_init(pingvpn_init);
module_exit(pingvpn_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("QiaoWei");

 
