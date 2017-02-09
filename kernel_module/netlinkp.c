#include <linux/string.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/sched.h>

#include "./../daemon/struct.h"

#define TASK_COMM_LEN 16

#define NETLINK_TEST 31 //自定义的协议号
//消息类型
#define NLMSG_SETECHO 0x11
#define NLMSG_COFIG 0x12

#define MAX_LENGTH 1024

static u32 pid = 0;
static struct sock *sk; //内核端socket
static struct _CC_Config k_config;

_CC_Config *get_config(void){
    return &k_config;
}

static void netlink_kernel_recv(struct sk_buff *skb)  
{
    struct nlmsghdr *nlh;  
    void *payload;  
    struct sk_buff *out_skb;  
    void *out_payload;  
    struct nlmsghdr *out_nlh;  
    int payload_len; // with padding, but ok for echo
    long content_addr; 
    int l;

    nlh = nlmsg_hdr(skb);  
    switch(nlh->nlmsg_type)  
    {  
        case NLMSG_SETECHO:  
            break;  
        case NLMSG_COFIG:  
            payload = nlmsg_data(nlh);  
            payload_len = nlmsg_len(nlh);  
            printk("[Module:recv]: payload length : %d\n", payload_len);  
            printk("[Module:recv]: recieved: %s, from: %d\n", (char *)payload, nlh->nlmsg_pid);
            pid = nlh->nlmsg_pid;
            out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff
            if (!out_skb){
                printk("[Module:recv]: fail to create skb\n");
                return;
            }
            out_nlh = nlmsg_put(out_skb, 0, 0, NLMSG_SETECHO, payload_len + strlen("rule address []") + 2, 0); 
            //填充协议头数据
            if (!out_nlh){
                printk("[Module:send]: fail to make the message\n");
                return;
            }
            out_payload = nlmsg_data(out_nlh);

            kstrtoul(payload, 10, &content_addr);
            memcpy(&k_config, (_CC_Config *)content_addr, sizeof(_CC_Config));
            printk("[Module:rule]: TCP: \t%d\n", k_config.TCP);
            printk("[Module:rule]: UDP: \t%d\n", k_config.UDP);
            printk("[Module:rule]: Len: \t%d\n", k_config.length);
            printk("[Module:rule]: Port: \t%d\n", k_config.port);

            for(l = 0; l < k_config.length; l++){
                printk("[Module:rule]: Site: \t%s:%d\n", k_config.arr[l].IP, k_config.arr[l].port);
            }
            sprintf(out_payload, "rule address [%x]\n", (unsigned int)content_addr); // 在响应中加入字符串，以示区别
            if(nlmsg_unicast(sk, out_skb, nlh->nlmsg_pid) < 0){
                //如果发送失败，则打印警告并退出函数
                printk("[Module:send]: fail in unicasting out_skb\n");
                return;
            }
            printk("[Module:send]: send ok\n");
            break;  
        default:  
            printk("[Module:recv]: unknow msgtype recieved!\n");  
    }  
    return;
}  

//发送netlink消息message
int netlink_kernel_send(char* message)  
{
    struct sk_buff *out_skb;  
    void *out_payload;  
    struct nlmsghdr *out_nlh; 
    out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff
    if (!out_skb){
        printk("[Module:recv]: fail to create skb\n");
        return -1;
    }
    out_nlh = nlmsg_put(out_skb, 0, 0, NLMSG_SETECHO, MAX_LENGTH, 0); //填充协议头数据
    if (!out_nlh){
        printk("[Module:send]: fail to make the message\n");
        return -1;
    }
    out_payload = nlmsg_data(out_nlh);  
    strcpy(out_payload, ""); // 在响应中加入字符串，以示区别
    strcat(out_payload, message);
    if(nlmsg_unicast(sk, out_skb, pid) < 0){
        //如果发送失败，则打印警告并退出函数
        printk("[Module:send]: fail in unicasting out_skb\n");
        return -1;
    }
    printk("[Module:send]: send ok\n");
    return 0;
}


int ConnectControl(char *info)
{
    printk("[Module:6]: info : %s \n", info);
    if(pid != 0){
        netlink_kernel_send(info);
    }
    return 0;
}

void netlink_init(void)  
{
    k_config.TCP = 0;
    k_config.UDP = 0;
    k_config.port = -1;
    k_config.length = 0;
    struct netlink_kernel_cfg nlcfg = {  
        .input = netlink_kernel_recv,  
    }; 
    printk("[Module:3]: begin to initialize netlink in kernel\n");
     
    sk = netlink_kernel_create(&init_net, NETLINK_TEST, &nlcfg); 
    if (!sk) {  
        printk("[Module:3]: netlink create error!\n");  
    } else {
	printk("[Module:3]: netlink create ok!\n");
    }
    printk("[Module:4]: kernel module initialized!\n");
}  

void netlink_release(void) {
    if (sk != NULL){
        printk("[Module:exit]: existing...\n");
	netlink_kernel_release(sk);
    }
}
