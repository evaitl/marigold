#include <linux/types.h>
#include <linux/bitmap.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/export.h>

static bool sdfp_kill_doublefetch; 
static DECLARE_BITMAP(sdfp_ignored_calls, NR_syscalls) = { 0 };
static DECLARE_BITMAP(sdfp_multiread_reported, NR_syscalls) = { 0 };


/**
 * Set up the bitfields or other data for sdfp.
 */
static int __init sdfp_init(void)
{
	set_bit(__NR_write, sdfp_ignored_calls);
	set_bit(__NR_execve, sdfp_ignored_calls);
	set_bit(__NR_futex, sdfp_ignored_calls);
	return 0;
}
module_init(sdfp_init);

/**
 * Need to merge the `to` buf with the buf in cn. The `to` buf is `(end-start)` long
 * and the userspace location starts at `start`.
 *
 */
static void merge_sdfp(uint8_t *to, struct sdfp_node *cn,
                       uintptr_t start, uintptr_t end)
{
	// Need to allocate and copy a new buffer.
	const uintptr_t new_start = min(start, cn->start);
	const uintptr_t new_end = max(end, cn->end);
	uint8_t *buf = kmalloc(new_end - new_start, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ALERT "Kmalloc failure in merge_sdfp()");
		return;
	}
	// First copy over from to, then from cn->buf so data gets
	// overwritten with original data. Yes, this may be slightly
	// inefficient.
	memcpy(&buf[start - new_start], &to[0], end - start);
	memcpy(&buf[cn->start - new_start], &cn->buf[0], cn->end - cn->start);
	kfree(cn->buf);
	cn->buf = buf;
	cn->start = new_start;
	cn->end = new_end;
}
/*
 * Return true if there was a node overlap with `to` buf.
 */
static bool overlap_check(uint8_t *to, struct sdfp_node *cn,
                          uintptr_t start, uintptr_t end)
{
	// Compare the overlapped bytes.
	const int nr = syscall_get_nr(current, current_pt_regs());
	// Double Fetch Detected?
	const bool dfd =
                memcmp(&to[min((unsigned)(start-cn->start),0u)],
                       &cn->buf[min(0u,(unsigned)(cn->start-start))],
                       min(cn->end-start,end-cn->start)) != 0;

	if ((start > cn->end) || (end < cn->start))
		return false;
	// Some kind of multi-fetch happened.

	if (!test_and_set_bit(nr, sdfp_multiread_reported))
		printk(KERN_ALERT "SDFP multiread seen in pid %d syscall %d",
		       current->pid, nr);
	if (start < cn->start || end > cn->end)
		merge_sdfp(to, cn, start, end); // We gotta reallocate the cn->buf.
	if (dfd) {
		memcpy(to, &cn->buf[start - cn->start], end - start);
		printk(KERN_ALERT "SDFP double fetch protected in pid %d, syscall %d",
		       current->pid, nr);
		if (sdfp_kill_doublefetch) {
			printk(KERN_ALERT "SDFP: Killing pid %d", current->pid);
			kill_pid(find_vpid(current->pid), SIGKILL, 1);
		}
	}
	return true;
}

/**
 * sdfp_check - Check for double fetch attacks.
 * @to: Result location
 * @from: Source address, in user space
 * @n: Amount to check.
 *
 * Context: user context only.
 *
 *
 * At this point, n bytes have already been copied to `to`.  This
 * ensures that we can check and fix `n` bytes without a fault.
 *
 * If the data hasn't been seen before, copy the data into a sdfp_node on `current`.
 *
 * If data has been seen before (in this syscall), make sure it hasn't changed.
 *
 * If data has changed and the syscall isn't in `sdfp_ignored_calls`,
 * overwrite with saved data. Send a SIGKILL if `sdfp_kill` is set.
 *
 */
void sdfp_check(void *to, const void __user *from,
		unsigned long n)
{
	int nr = syscall_get_nr(current, current_pt_regs());
	bool merged = false;
	struct sdfp_node *cn = current->sdfp_list;
	struct sdfp_node *nn = 0;
	const uintptr_t start = (uintptr_t) from;
	const uintptr_t end = start + n;
	if (test_bit(nr, sdfp_ignored_calls))
		return;
	while (cn && !merged) {
		// Look for overlaps and merges. Check bytes if overlaps.
		merged = overlap_check(to, cn, start, end);
		cn = cn->next;
	}
        if(merged){
                // TODO: Walk sdfp_list and merge any nodes that need to be merged. 
        }else {
		// No
		nn = kmalloc(sizeof(struct sdfp_node), GFP_KERNEL);
		if (!nn)
			goto kmalloc_failed;
		nn->buf = kmalloc(n, GFP_KERNEL);
		if (!nn->buf)
			goto kmalloc_failed;
		memcpy(nn->buf, to, n);
		nn->next = current->sdfp_list;
		nn->start = start;
		nn->end = end;
		current->sdfp_list = nn;
	}
	return;
kmalloc_failed:
	kfree(nn);
	printk(KERN_ALERT "Kmalloc failed in sdfp_check");
}
EXPORT_SYMBOL(sdfp_check);
void sdfp_clear(void)
{
	struct sdfp_node *cn = current->sdfp_list;
	current->sdfp_list = 0;
	while (cn) {
		struct sdfp_node *nn = cn->next;
		kfree(cn->buf);
		kfree(cn);
		cn = nn;
	}
}
EXPORT_SYMBOL(sdfp_clear);
