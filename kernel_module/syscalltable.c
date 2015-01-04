#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
                                    
void *get_system_call(void)
{
    struct{
        unsigned short  limit;
        unsigned int    base;
    } __attribute__ ((packed)) idtr;
    struct{
        unsigned short  offset_low;
        unsigned short  segment_select;
        unsigned char   reserved,   flags;
        unsigned short  offset_high;
    } __attribute__ ((packed)) * idt;
    unsigned long system_call;
    asm ("sidt %0" : "=m" (idtr));
    idt = ( void * ) ( idtr.base + 8 * 0x80 );
    printk("[Module:1]: get struct idt address : %x\n" ,(unsigned int)idt);
    system_call = (idt->offset_high << 16) | idt->offset_low;
    printk("[Module:1]: return the system call entrance address : %x\n" ,(unsigned int)system_call);
    return (void *)(system_call);
}

void *get_sys_call_table(void)
{
    void *system_call = get_system_call();
    unsigned char *p;
    unsigned long sct;
    int count = 0;
    p = (unsigned char *) system_call;
    //"\xff\x14\x85" call 指令
    while (!((*p == 0xff) && (*(p+1) == 0x14) && (*(p+2) == 0x85))){
        p++;
        if (count++ > 500) {
            count = -1;
            break;
        }
    }  
    printk("[Module:1]: find the call instruction address : %x\n" ,(unsigned int)p);
    if (count != -1){
        p += 3;
        sct = *((unsigned long *) p);
    } else {
        sct = 0;
    }
    printk("[Module:1]: return the system call table address, is %x\n" ,(unsigned int)sct);
    return ((void *) sct);
} 

// clear WP bit of CR0, and return the original value
unsigned int clear_and_return_cr0(void)
{
    printk("[Module:1]: clearing WP bit of CR0\n");
    unsigned int cr0 = 0;
    unsigned int ret;
    asm volatile ("movl %%cr0, %%eax" : "=a"(cr0));
    ret = cr0;
    /* clear the 20 bit of CR0, a.k.a WP bit */
    cr0 &= 0xfffeffff;
    asm volatile ("movl %%eax, %%cr0" : : "a"(cr0));
    return ret;
}

// set CR0 with new value
void setback_cr0(unsigned int val)
{
    printk("[Module:2]: setting CR0 with new value\n");
    asm volatile ("movl %%eax, %%cr0" : : "a"(val));
}
