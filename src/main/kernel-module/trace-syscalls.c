/*********************************************************************
 *  This is part of DroidTracer
 *  (http://kuester.multics.org/DroidTracer).
 *
 *  Copyright (c) 2013-2015 by Jan-Christoph Küster
 *  <jckuester@gmail.com>
 *
 *  DroidTracer is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  DroidTracer is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with DroidTracer.  If not, see
 *  <http://www.gnu.org/licenses/>.
 ********************************************************************/

#include <linux/init.h>		/* __init and __exit macros */
#include <linux/kernel.h>	/* KERN_INFO macros */
#include <linux/module.h>	/* required for all kernel modules */
#include <linux/moduleparam.h>  /* passing cmd line arguments to a module */
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/cred.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/time.h>
#include <net/genetlink.h>
#include <linux/fdtable.h>
#include <../drivers/staging/android/binder.h>

#include "genl-endpoint.h"
#include "helper.h"
#include "trace-syscalls.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jan-Christoph Kuester <jckuester@gmail.com>");
MODULE_DESCRIPTION("Trace Android's Binder and other syscalls via kprobes");

/* global variables */
D(static int counter = 0;)
static char interface[100];
/* if set to 0 (UID 0 is root), all apps are traced */
int lowest_uid_traced = INT_MAX;
static int trace_uids[5] = { -1, -1, -1, -1, -1 };

module_param(lowest_uid_traced, int, 0000);
MODULE_PARM_DESC(myint, "Trace all UIDs above threshold");
module_param_array(trace_uids, int, NULL, 0000);
MODULE_PARM_DESC(trace_uids, "Trace this specific UIDs (max. 5 entries)");

static int trace_binder_thread_write(struct binder_proc *proc,
				struct binder_thread *thread,
				void __user *buffer,
				int size, signed long *consumed);
asmlinkage long trace_sys_open(const char __user *filename, int flags, int mode);
long trace_sys_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen);

/*
 * trace_binder_transaction() is not exported, and therefore cannot be
 * traced by jprobes. So, we trace the next function upwards that is
 * exported trace_binder_thread_write()
 */
static int trace_binder_thread_write(struct binder_proc *proc,
				struct binder_thread *thread,
				void __user *buffer,
				int size, signed long *consumed)
{
	uint32_t cmd;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;
	uint8_t uid_traced;
	char *tmp;
	uint8_t *data_ptr;
	uint8_t iface_len;
	uint8_t *iface_ptr;
	struct timespec ts;
	struct binder_transaction_data tr;
	
	uid_traced = (get_appuid(current->cred->uid) != NULL);

	/* nerver monitor droidtracer itself 
	 * OR UIDs under threshold (if UID is not explicitly monitored) */
	if (current->cred->uid == droidtracer_uid || 
		(current->cred->uid < lowest_uid_traced && 
			!uid_traced &&
			whitelist_empty))
		jprobe_return();
	
	while (ptr < end && thread->return_error == BR_OK) {
		if (get_user(cmd, (uint32_t __user *)ptr))
			//return -EFAULT;
			jprobe_return();
		ptr += sizeof(uint32_t);
		if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
			binder_stats.bc[_IOC_NR(cmd)]++;
			proc->stats.bc[_IOC_NR(cmd)]++;
			thread->stats.bc[_IOC_NR(cmd)]++;
		}

		if (cmd != BC_TRANSACTION)  // || cmd == BC_REPLY
			jprobe_return();
		
		/* handle (target method Remote Interface)
		 * sender_pid/euid is not copied from user space 
		 * code (method ID)
		 * data.ptr.buffer (Parcel - Input/Output Parameters)
		 */         
		
		if (copy_from_user(&tr, ptr, sizeof(tr)))
			//return -EFAULT;
			jprobe_return();
		
		
		if (tr.data_size < 4) {
			printk(KERN_WARNING
				"RV; untraced BC_TRANSACTION, data_size = %d\n",
				tr.data_size);
			jprobe_return();
		}
		
		data_ptr = (uint8_t *) tr.data.ptr.buffer;
		iface_len = *(data_ptr + 4);
		iface_ptr = (uint8_t *) data_ptr + 8;
		
		/* get time in sec since 1970 (epoch) */
		getnstimeofday(&ts);
		
		if (iface_len < sizeof(interface)) {
			binder_data_tostr(iface_ptr, iface_len, interface);
		} else {
			printk(KERN_WARNING "RV; interface name too long");
			jprobe_return();
		}
		
		/* DON'T trace interfaces in blacklist 
		   but those in whitelist */
		if (get_blacklisted_iface_len(iface_len+1)) {
			struct rbnode_interface *iface_node =
				get_blacklisted_iface(interface, iface_len+1);
			if (iface_node) {
				/* service in black or white list */
				if (iface_node->whitelist) {
					/* entry is in blacklist */
					jprobe_return();
				}
				/* in whitelist, so continue tracing */
				goto continue_tracing;
			}			
		}		
		if (!uid_traced && current->cred->uid < lowest_uid_traced)
			jprobe_return();		
		
	continue_tracing:		
		/*
		  if (strstr(iface, "android.app.IActivityManager")) {
		  D(printk("RV; serv_name=%s\n", iface));
		  D(printk("RV; code=%d\n", tr.code));
		  D(printk("RV; flags=%d\n", tr.flags));
		  D(printk("RV; sender_pid=%d\n", tr.sender_pid));
		  D(printk("RV; sender_euid=%d\n", tr.sender_euid));
		  D(printk("RV; data_size=%d\n", tr.data_size));
		  D(printk("RV; offsets_size=%d\n", tr.offsets_size));
		  }
		*/

		tmp = strrchr(interface, '.');			
		if (tmp && (tmp[1] != '\0'))
			D(printk(KERN_INFO
					"RV; %d, uid: %d, %s, code: %d, size: %d\n",
					counter++, current->cred->uid, tmp+1, tr.code,
					tr.data_size));
		else
			D(printk(KERN_INFO
					"RV; %d, uid: %d, %s, code: %d\n, size: %d",
					counter++, current->cred->uid, interface, tr.code,
					tr.data_size));
		
		N(send_event(tr.code,  current->cred->uid, ts.tv_sec,
				tr.data_size, tr.data.ptr.buffer, NULL));
		
		D(print_debug(tr, data_ptr));
	}
	
	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	/* NEVER REACHED */
	return 0; 
}

asmlinkage long trace_sys_open(const char __user *filename, int flags, int mode)
{  
	char *tmp;  
	int ret;
	struct timespec ts;

	if (!intercept(current->cred->uid)) 
		jprobe_return();
	
	printk("RV; sys_open; uid=%d\n", current->cred->uid);
	
	tmp = __getname();
	//tmp = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	ret = strncpy_from_user(tmp, filename, PATH_MAX + 1);
	if (ret <= 0) {
		putname(tmp);
		jprobe_return();
	}
	
	if (!strstr(tmp, "/system/") && !strstr(tmp, "/proc/")) {
		//if (strstr(tmp, "sdcard") || strstr(tmp, "/storage/emulated")) {
		// get time in sec since 1970 (epoch)
		getnstimeofday(&ts);
		
		N(send_event(0, current->cred->uid, (uint32_t) ts.tv_sec,
				strlen(tmp), tmp, "sys_open"));	  
		printk("RV; sys_open; uid=%d, file=%s, flags=0x%x, mode=0o%03o\n",
			(current->cred)->uid, tmp, flags, mode);
	}
	
	putname(tmp);
	//kfree(tmp);
	jprobe_return();
	return 0;  
}

long trace_sys_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	struct timespec ts;
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
	
	/* only monitor apps in list apps_uid_to_monitor */  
	if (!intercept(current->cred->uid)) 
		jprobe_return();
	
	printk("RV; sys_connect; uid=%d\n", current->cred->uid);
	
	getnstimeofday(&ts);
 
	if (addr->sa_family == AF_INET) {
		ipv4 = (struct sockaddr_in *) addr;
		D(printk("RV; sys_connect, ipv4; ip = %pI4, uid = %d\n",
				&ipv4->sin_addr.s_addr, current->cred->uid);)
			N(send_event(0, current->cred->uid, ts.tv_sec,
					sizeof(unsigned long), &ipv4->sin_addr.s_addr, "sys_connect"));	  
	} else if (addr->sa_family == AF_INET6) {
		// u_int8_t  s6_addr[16]; 128 bit
		ipv6 = (struct sockaddr_in6 *) addr;
		D(printk("RV; sys_connect, ipv6; ip = %pI6, uid = %d\n",
				(ipv6->sin6_addr).s6_addr, current->cred->uid);)
			N(send_event(0, current->cred->uid, (uint32_t) ts.tv_sec,
					16, (uint8_t *) (ipv6->sin6_addr).s6_addr, "sys_connect"));	  
	} else {
		/*
		  p = current;
		  D(printk("RV; sys_connect; fd = %d, addr = %d,"
		  " pid = %d, uid = %d, euid = %d\n",
		  sockfd, addr->sa_family,
		  p->pid, (p->cred)->uid, (p->cred)->euid));
		*/
	}
	
  jprobe_return();
  return 0;
}

/*
 * common handler for sys_read() and sys_write(), as function have
 * same signature
 */
long handle_read_write(unsigned int fd, const char __user *buf,
		size_t count, bool write)
{
	struct timespec ts;
	char *buf_tmp;  
	//int i;
	
	/* only monitor apps in list apps_uid_to_monitor */
	if (!intercept(current->cred->uid)) 
		jprobe_return();
	
	// buf  
	buf_tmp = kmalloc(count, GFP_KERNEL);
	if (copy_from_user(buf_tmp, buf, count))
		goto out;
	getnstimeofday(&ts);
	
	if (write) {
		D(printk("RV; sys_write; uid = %d, fd = %d, count = %zd, buf=",
				current->cred->uid, fd, count));
		N(send_event(0, current->cred->uid, (uint32_t) ts.tv_sec,
				count, buf_tmp, "do_write"));
	} else {
		D(printk("RV; sys_read; uid = %d, fd = %d, count = %zd, buf=",
				current->cred->uid, fd, count));
		N(send_event(0, current->cred->uid, (uint32_t) ts.tv_sec,
				count, buf_tmp, "do_read"));
	}
	
#ifdef DEBUG_ON
	for (i = 0; i < count; i++)
		printk("%c", buf_tmp[i]);
	printk("\n");
#endif
	
 out:
	kfree(buf_tmp);
	jprobe_return();
	return 0;
}

// TODO: do_read instead of sys_read?
long trace_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	return handle_read_write(fd, buf, count, false);  
}

// TODO: do_read instead of sys_write?
long trace_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	return handle_read_write(fd, buf, count, true);
}

/**
 * sys_send - only when the socket is in a connected state; calls sys_sendto 
 * with NUL address in net/socket.c
 * Also sys_send is equivalent to write, just different flags
 * sys_sendto - is for UDP, destination specified each time
 * sys_sendmsg - the only necessary cal; send and sendto are just a wrapper
 */
//long sys_send(int, void __user *, size_t, unsigned) 

asmlinkage long trace_sys_sendto(int fd, void __user *buff, size_t len,
				unsigned flags, struct sockaddr __user *addr,
				int addr_len)
{
	struct timespec ts;
	char *buff_tmp;  
	int i;
	
	/* only monitor apps in list apps_uid_to_monitor  */
	if (!intercept(current->cred->uid)) 
		jprobe_return();
	
	printk("RV; sys_sendto; uid = %d\n", current->cred->uid);
	
	buff_tmp = kmalloc(len, GFP_KERNEL);
	if (copy_from_user(buff_tmp, buff, len))
		goto out;
	getnstimeofday(&ts);
	
	//#ifdef DEBUG_ON
	printk("RV; sys_sendto; uid = %d, fd = %d, len = %zd, buff=",
		current->cred->uid, fd, len);
	for (i = 0; i < len; i++)
		printk("%c", buff_tmp[i]);
	printk("\n");
	//#endif
	
	N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, len,
			buff_tmp, "sys_sendto"));
	
 out:
	kfree(buff_tmp);
	jprobe_return();
	return 0;
}

long handle_sendmsg_readmsg(int fd, struct msghdr __user * msg,
			unsigned int flags, bool send)
{
	struct timespec ts;
	struct msghdr *msg_tmp;
	struct iovec *msg_iov_tmp;
	//void *iov_tmp;
	uint8_t *iov_tmp;
	int i;
	int j;
	
	/* only monitor apps in list apps_uid_to_monitor  */
	if (!intercept(current->cred->uid)) 
		jprobe_return();
	
	printk("RV; sys_sendmsg/recvmsg; uid=%d\n", current->cred->uid);
	
	msg_tmp = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
	if (copy_from_user(msg_tmp, msg, sizeof(struct msghdr)))
		goto out_msg;
	
	msg_iov_tmp = kmalloc(msg_tmp->msg_iovlen * sizeof(struct iovec),
			GFP_KERNEL);
	if (copy_from_user(msg_iov_tmp, msg_tmp->msg_iov,
				msg_tmp->msg_iovlen * sizeof(struct iovec))) {
		kfree(msg_iov_tmp);
		goto out_msg;
	}
	
	for (i = 0; i < msg_tmp->msg_iovlen; i++) {		
		iov_tmp = kmalloc(msg_iov_tmp[i].iov_len, GFP_KERNEL);
		if (copy_from_user(iov_tmp, msg_iov_tmp[i].iov_base,
					msg_iov_tmp[i].iov_len)) {
			kfree(msg_iov_tmp);
			kfree(iov_tmp);
			goto out_msg;
		}
		getnstimeofday(&ts); 
		
		if (send) {
			printk("RV; sys_sendmsg; uid=%d, fd = %d, msg_iovlen=%d, iov_len=%d, iov=",
				current->cred->uid, fd, msg_tmp->msg_iovlen, msg_iov_tmp[i].iov_len);
			N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec,
					msg_iov_tmp[i].iov_len, iov_tmp, "sys_sendmsg"));
		} else {
			printk("RV; sys_recvmsg; uid=%d, fd = %d, msg_iovlen=%d, iov_len=%d, iov=",
				current->cred->uid, fd, msg_tmp->msg_iovlen, msg_iov_tmp[i].iov_len);
			N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, msg_iov_tmp[i].iov_len, iov_tmp, "sys_recvmsg"));
		}
		//#ifdef DEBUG_ON   
		for (j = 0; j < msg_iov_tmp[i].iov_len; j++)
			printk("%c", iov_tmp[j]);
		printk("\n");   
		//#endif
		
		kfree(iov_tmp);          
	}
	
	kfree(msg_iov_tmp);
	
 out_msg:
	kfree(msg_tmp);
	jprobe_return();
	return 0;
}

asmlinkage long trace_sys_sendmsg(int fd, struct msghdr __user *msg,
				unsigned flags)
{
	return handle_sendmsg_readmsg(fd, msg, flags, true);      
}

/* recv() - only on a connected socket, identical to recvfrom() with a
 * NULL src_addr argument 
 * recvmsg() - equivalent to sendmsg()
 */
asmlinkage long trace_sys_recvmsg(int fd, struct msghdr __user * msg,
				unsigned int flags)
{
  return handle_sendmsg_readmsg(fd, msg, flags, false);
}

/*
 * do_execve() is system-independent routine of sys_execve()
 * TODO intercept argv
 */
int trace_do_execve(char *filename, char __user *__user *argv,
			   char __user *__user *envp, struct pt_regs *regs)
{
	int ret;
	struct timespec ts;
	int i = 0;
	char *tmp;
	
	/* only monitor apps in list apps_uid_to_monitor  */
	if (!intercept(current->cred->uid)) {
		jprobe_return();
		return 0;
	}
	
	printk("RV; do_execve; uid=%d\n", current->cred->uid);
	
	getnstimeofday(&ts);  
	
	// TODO argv
	
	// count how many arguments
	if (argv) {
		for (;;) {
			char __user *p;
			
			if (get_user(p, argv))
				goto out;
			if (!p)
				break;
			argv++;
			if (i++ >= 10)
				break;
			tmp = __getname();
			ret = strncpy_from_user(tmp, p, PATH_MAX + 1);
			if (ret <= 0) {
				putname(tmp);      
				break;
			}
			printk("RV; do_execve; arg=%s\n", p);
			putname(tmp);
			cond_resched();
		}
	}
	
	printk("RV; do_execve; path = %s, uid = %d, count_args = %d\n",
	       filename, current->cred->uid, i);
	N(send_event(0, current->cred->uid, (uint32_t) ts.tv_sec,
			strlen(filename), filename, "do_execve"));
	
 out:
	jprobe_return();
	return 0;
}

/* 
 *  system-independent routine of sys_fork 
 */
long trace_do_fork(unsigned long clone_flags, unsigned long stack_start,
		   struct pt_regs *regs, unsigned long stack_size,
		   int __user *parent_tidptr, int __user *child_tidptr)
{
	struct timespec ts;
	
	/* only monitor apps in list apps_uid_to_monitor  */
	if (!intercept(current->cred->uid)) 
		jprobe_return();
	
	getnstimeofday(&ts);
	
	D(printk("RV; do_fork; parent_tidptr = 0x%p, child_tidptr = 0x%p,"
		 " pid = %d, uid = %d, euid = %d\n",
		 parent_tidptr, child_tidptr,
		 current->pid, current->cred->uid, (current->cred)->euid);)
		N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, 0,
				NULL, "do_fork"));
	
	jprobe_return();
	return 0;
}

asmlinkage long trace_sys_uselib(const char __user *library)
{
	char *library_tmp;  
	int ret;
	struct timespec ts;
	
	/* only monitor apps in list apps_uid_to_monitor  */
	if (!intercept(current->cred->uid))
		jprobe_return();
	
	printk("RV; sys_uselib; uid=%d\n", current->cred->uid);
	
	library_tmp = __getname();
	ret = strncpy_from_user(library_tmp, library, PATH_MAX + 1);
	if (ret <= 0) 
		goto out;
	getnstimeofday(&ts);
	
	printk("RV; sys_uselib; library = %s, uid = %d",
		library_tmp, current->pid);
	N(send_event(0, current->cred->uid, (uint32_t) ts.tv_sec,
			strlen(library_tmp), library_tmp, "sys_uselib"));
	
 out:
	putname(library_tmp);
	jprobe_return();
	return 0;
}


/*
  asmlinkage long trace_sys_socket(int family, int type, int protocol) {
  printk("RV; socket family=%d, uid=%d.\n", family, current->cred->uid);
  
  jprobe_return();
  return 0;
  }
*/

#define CREATE_JPROBE(victim, target)		     \
        static struct jprobe jp_##victim = {	     \
                .entry = target,		     \
                .kp.symbol_name = #victim,	     \
        }

CREATE_JPROBE(binder_thread_write, trace_binder_thread_write);
//CREATE_JPROBE(do_execve, trace_do_execve);
//CREATE_JPROBE(sys_sendto, trace_sys_sendto);
//CREATE_JPROBE(sys_sendmsg, trace_sys_sendmsg);
//CREATE_JPROBE(sys_recvmsg, trace_sys_recvmsg);
//CREATE_JPROBE(do_fork, trace_do_fork);
//CREATE_JPROBE(sys_read, trace_sys_read);
//CREATE_JPROBE(sys_write, trace_sys_write);
//CREATE_JPROBE(sys_open, trace_sys_open);
//CREATE_JPROBE(sys_uselib, trace_sys_uselib);
//CREATE_JPROBE(sys_connect, trace_sys_connect);
//CREATE_JPROBE(sys_socket, trace_sys_socket);

/* Note: prefix of jprobe objects 
is defined as jp_ in CREATE_JPROBE */
#define NUM_PROBES 1
static struct jprobe *jprobes[NUM_PROBES] = {
	&jp_binder_thread_write
	//&jp_sys_socket
	//&jp_sys_sendto,
	//&jp_sys_sendmsg,  
	//&jp_sys_recvmsg,
	//&jp_do_fork,
	//&jp_sys_read,
	//&jp_sys_write,
	//&jp_sys_open,
	//&jp_sys_connect,
	//&jp_sys_uselib,
	//&jp_do_execve
};

static int __init droidtracer_init(void)
{
	int err;
	int i;
	
	/* plant jprobes */  
	err = register_jprobes(jprobes, NUM_PROBES);
	if (err) {
		printk(KERN_ERR "RV; register_jprobes failed: %d\n", err);
		goto out;
	}
	printk(KERN_INFO "RV; planted %d jprobes\n", NUM_PROBES);  

	/* registers new family name with
	   generic netlink mechanism */
	err = genl_register_family(&droidtracer_family);
	if (err) {
		printk(KERN_ERR
			"RV; failed to register netlink family: %d\n", err);
		goto out;
	}

	/* register the netlink operations */
	err = droidtracer_register_genl_ops();
	if (err)
		goto out;
	
	printk(KERN_INFO "RV; netlink operations registered\n");

	/* specific UIDs being traced via module parameter */
	for (i = 0; i < (sizeof trace_uids / sizeof (int)); i++) {
		if (trace_uids[i] > 0)
			trace_appuid(trace_uids[i]);
	}
	return 0;

out:
	unregister_jprobes(jprobes, NUM_PROBES);
	return err;
}

static void __exit droidtracer_exit(void)
{
	int err;

	unregister_jprobes(jprobes, NUM_PROBES);
	err = genl_unregister_family(&droidtracer_family);
	if(err)
		printk(KERN_ERR
			"RV; failed to unregister netlink family: %d\n", err);

	printk(KERN_INFO "RV; Good bye! Droidtracer module unloaded\n");
}

module_init(droidtracer_init);
module_exit(droidtracer_exit);
