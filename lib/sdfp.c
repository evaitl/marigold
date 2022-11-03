#include <linux/types.h>
#include <linux/bitops.h>
#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>

static bool sdfp_kill; 
static DECLARE_BITMAP(sdfp_ignored_calls,NR_syscalls) = {0};
static DECLARE_BITMAP(sdfp_multiread_reported,NR_syscalls) ={0};


/**
   Set up the bitfields or other data for sdfp. 
 */
static int  __init sdfp_init(void){
        set_bit(__NR_write,sdfp_ignored_calls);
        set_bit(__NR_execve,sdfp_ignored_calls);
        set_bit(__NR_futex,sdfp_ignored_calls);
        // XXXX
        clear_bit(__NR_futex,sdfp_multiread_reported);
        sdfp_kill=0;
        return 0;
}
module_init(sdfp_init);
/**
   sdfp_check - Check for double fetch attacks.
   @to: Result location
   @from: Source address, in user space
   @n: Amount to check.
   
   Context: user context only.
   
   
   At this point, n bytes have already been copied to `to`.  This
   ensures that we can check and fix `n` bytes without a fault.
   
   If the data hasn't been seen before, copy the data into a sdfp_node on `current`.

   If data has been seen before (in this syscall), make sure it hasn't changed.

   If data has changed and the syscall isn't in `sdfp_ignored_calls`,
   overwrite with saved data. Send a SIGKILL if `sdfp_kill` is set.
   
 */
void sdfp_check(void *to, const void __user *from,
                unsigned long n){
#if 0        
        int nr=syscall_get_nr(current,current_pt_regs());
        if (test_bit(nr,sdfp_ignored_calls)){
                return;
        }
        bool mem_changed=0;

        
        
        if (mem_changed && sdfp_kill){
                kill_pid(current->pid,SIGKILL,1);
        }
#endif
}
EXPORT_SYMBOL(sdfp_check);
void sdfp_clear(void){
        struct sdfp_node *cn=current->sdfp;
        current->sdfp=0;
        while(cn){
                struct sdfp_node *nn=cn->next;
                kfree(cn->buf);
                kfree(cn);
                cn=nn;
        }
}
EXPORT_SYMBOL(sdfp_clear);
