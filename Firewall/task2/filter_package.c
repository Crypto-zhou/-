#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#define MAX_RULE_NUM 10

static struct nf_hook_ops FilterHookRule[MAX_RULE_NUM];
static int regist_num = 0;

int eq_daddr(const struct iphdr *iph, const char *ip_addr)
{
    //check if the dst ip address equals the given address
    char source[16];
    snprintf(source, 16, "%pI4", &iph->daddr);
    if (strcmp(source, ip_addr) == 0)
        return 1;
    return 0;
}

int eq_saddr(const struct iphdr *iph, const char *ip_addr)
{
    //check if the src ip address equals the given address
    char source[16];
    snprintf(source, 16, "%pI4", &iph->saddr);
    if (strcmp(source, ip_addr) == 0)
        return 1;
    return 0;
}

unsigned int telnetFilter_1(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state)
// rule for task 1.1: Prevent A from doing `telnet` to Machine B
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && 
      eq_daddr(iph, "10.0.2.5") && eq_saddr(iph, "10.0.2.4"))
    {
        printk(KERN_INFO "Dropping telnet from %pI4 packet to %pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

unsigned int telnetFilter_2(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state)
// rule for task 1.2: Prevent B from doing `telnet` to Machine A
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && 
      eq_daddr(iph, "10.0.2.4") && eq_saddr(iph, "10.0.2.5"))
    {
        printk(KERN_INFO "Dropping telnet from %pI4 packet to %pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

unsigned int block_IP(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;
    if ((tcph->dest == htons(8000) || tcph->dest == htons(443)) 
    && eq_daddr(iph, "47.103.222.234")&& eq_saddr(iph, "10.0.2.4"))
    {
        printk(KERN_INFO "Dropping http/https from %pI4 packet to %pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}
unsigned int block_SSH(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;
    if ((iph->protocol == IPPROTO_TCP && tcph->dest==htons(22)))
    {
        printk(KERN_INFO "Dropping ssh from %pI4 packet to %pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

unsigned int block_UDP(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;
    if ((iph->protocol == IPPROTO_UDP))
    {
        printk(KERN_INFO "Dropping UDP from %pI4 packet to %pI4\n", &iph->saddr, &iph->daddr);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}




int setUpFilter(void)
{
    int i;
    printk(KERN_INFO "Registering filters.\n");
    FilterHookRule[0] = (struct nf_hook_ops){.hook = telnetFilter_1, .hooknum = NF_INET_LOCAL_OUT, .pf = PF_INET, .priority = NF_IP_PRI_FIRST};
    FilterHookRule[1] = (struct nf_hook_ops){.hook = telnetFilter_2, .hooknum = NF_INET_LOCAL_IN, .pf = PF_INET, .priority = NF_IP_PRI_FIRST};
    FilterHookRule[2] = (struct nf_hook_ops){.hook = block_IP, .hooknum = NF_INET_LOCAL_OUT, .pf = PF_INET, .priority = NF_IP_PRI_FIRST};
    FilterHookRule[3] = (struct nf_hook_ops){.hook = block_SSH, 
      .hooknum = NF_INET_LOCAL_OUT, .pf = PF_INET, .priority = NF_IP_PRI_FIRST};
    FilterHookRule[4] = (struct nf_hook_ops){.hook = block_UDP, .hooknum = NF_INET_LOCAL_OUT,
     .pf = PF_INET, .priority = NF_IP_PRI_FIRST};
    // set the amount of filter rules
    regist_num = 5;

    for (i = 0; i < regist_num; i++)
        nf_register_hook(&FilterHookRule[i]);
    return 0;
}

void removeFilter(void)
{
    int i;
    printk(KERN_INFO "Filters are being removed.\n");
    //unregist hooks one by one
    for (i = 0; i < regist_num; i++)
        nf_unregister_hook(&FilterHookRule[i]);
    regist_num = 0;
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
