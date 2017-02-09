#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>

#include "./../daemon/struct.h"

MODULE_LICENSE("GPL");
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[20] = {
    AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
    AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
    AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
    AL(4), AL(5)
};

void netlink_release(void);
void netlink_init(void);
int ConnectControl(char *info);

void *get_sys_call_table(void);
unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);
_CC_Config *get_config(void);

void **sys_call_table;

void inet_ntoa(char* buf, struct in_addr ina)
{
    unsigned char *ucp = (unsigned char *)&ina;
    sprintf(buf, "%d.%d.%d.%d",
    ucp[0] & 0xff,
    ucp[1] & 0xff,
    ucp[2] & 0xff,
    ucp[3] & 0xff);
}
unsigned int inet_aton(char *buf)
{
    unsigned int tmpip[4] = {0};
    unsigned int tmpip32 = 0;
    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);
    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];
    return tmpip32;
}

asmlinkage long (*orig_sys_socketcall)(int call, unsigned long __user *args);
asmlinkage long hacked_sys_socketcall(int call, unsigned long __user *args)
{
    char info[256];
    unsigned long a[6];
    unsigned long a0, a1;
    int err;
    int len;
    int site_loop;
    char commandname[32];
    _CC_Config *k_config;

    //调用指令超出范围
    if (call < 1 || call > SYS_RECVMMSG)
        return -EINVAL;
    //长度出错
    len = nargs[call];
    if (len > sizeof(a))
        return -EINVAL;
    /* copy_from_user should be SMP safe. */
    if (copy_from_user(a, args, len))
        return -EFAULT;
    a0 = a[0];
    a1 = a[1];
    strncpy(commandname,current->comm,32);

    k_config = get_config();

    switch (call) {
        case SYS_SOCKET:
        {
            if (k_config->TCP == 1 && a0 == AF_INET && a1 == SOCK_STREAM /*&& a[2] == IPPROTO_TCP*/) {
	            sprintf(info,"process: %s, protocal TCP forbidden\n", commandname);
                ConnectControl(info);
	        return -EFAULT;
            }
            if (k_config->UDP == 1 && a0 == AF_INET && a1 == SOCK_DGRAM /*&& a[2] == IPPROTO_UDP*/) {
	            sprintf(info,"process: %s, protocol UDP forbidden\n", commandname);
                ConnectControl(info);
	        return -EFAULT;
            }
            break;
        }
        case SYS_BIND:
            break;
        case SYS_CONNECT:
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)a1;
            char buf[4*sizeof "123"];
            if(addr->sin_family == AF_INET){
                inet_ntoa(buf, addr->sin_addr);
            }
            if (addr->sin_family == AF_INET && htons(k_config->port) == addr->sin_port) {
                sprintf(info,"process: %s, IPv4 %s:%d forbidden\n", commandname, buf, ntohs(addr->sin_port));
                ConnectControl(info);
                return -EFAULT;
            }
            if (addr->sin_family == AF_INET6 && htons(k_config->port) == addr->sin_port){
                sprintf(info,"process: %s, IPv6 port %d forbidden\n", commandname, ntohs(addr->sin_port));
                ConnectControl(info);
            }

            for(site_loop = 0 ; site_loop != k_config->length; site_loop++){
                _CC_Site cc_site = k_config->arr[site_loop];
                //IPv4
                if(addr->sin_family == AF_INET){
                    if (addr->sin_addr.s_addr == inet_aton(cc_site.IP)) {
                        if (cc_site.port != -1 && htons(cc_site.port) == addr->sin_port){
                            sprintf(info,"process: %s, IPv4 %s:%d forbidden\n", commandname, buf, cc_site.port);
                            ConnectControl(info);
                            return -EFAULT;
                        } else if (cc_site.port == -1){
                            sprintf(info,"process: %s, IPv4 %s forbidden\n", commandname, buf);
                            ConnectControl(info);
	                    return -EFAULT;
                        }
                    }
                }
            }
            break;
        }
        case SYS_LISTEN:
            break;
        case SYS_ACCEPT:
            break;
        case SYS_GETSOCKNAME:
            break;
        case SYS_GETPEERNAME:
            break;
        case SYS_SOCKETPAIR:
            break;
        case SYS_SEND:
            break;
        case SYS_SENDTO:
            break;
        case SYS_RECV:
            break;
        case SYS_RECVFROM:
            break;
        case SYS_SHUTDOWN:
            break;
        case SYS_SETSOCKOPT:
            break;
        case SYS_GETSOCKOPT:
            break;
        case SYS_SENDMSG:
            break;
        case SYS_RECVMSG:
            break;
        default:
            break;
    }
    err = orig_sys_socketcall(call, args);
    return err;
}

static int __init connect_control_init(void)
{
    unsigned int orig_cr0;
    printk("[Module:init]: entrance of the kernel module\n");
    orig_cr0 = clear_and_return_cr0();
    sys_call_table = get_sys_call_table();
    orig_sys_socketcall = sys_call_table[__NR_socketcall];
    printk("[Module:init]: store the syscall : %x\n", (unsigned int)orig_sys_socketcall);
    sys_call_table[__NR_socketcall] = hacked_sys_socketcall;
    printk("[Module:init]: hack the syscall : %x\n", (unsigned int)hacked_sys_socketcall);
    setback_cr0(orig_cr0);
    //Initialize Netlink
    netlink_init();
    return 0;
}

static void __exit connect_control_exit(void)
{
    unsigned int orig_cr0;
    printk("[Module:exit]: begin to romove kernel module\n");
    orig_cr0 = clear_and_return_cr0();
    printk("[Module:exit]: reset the syscall : %x\n", (unsigned int)orig_sys_socketcall);
    sys_call_table[__NR_socketcall] = orig_sys_socketcall;
    setback_cr0(orig_cr0);
    netlink_release();  	
}

module_init(connect_control_init);
module_exit(connect_control_exit);
