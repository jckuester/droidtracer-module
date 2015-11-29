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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/cred.h>
#include <linux/kallsyms.h>
#include <../drivers/staging/android/binder.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/time.h>
#include <net/genetlink.h>
#include <linux/fdtable.h>
#include "comm_netlink.h"
#include "trace_syscalls.h"

extern int init_netlink(void);
extern int exit_netlink(void);
extern int send_event(uint8_t method_id, uint32_t app_uid, 
		      uint32_t time, int data_size, const void *data, char *sys_call);
extern struct rbnode_appuid *search_appuid(uint32_t appuid);
extern struct rbnode_services_len *search_service_len_blacklist(uint8_t service_name_len);
extern struct rbnode_service_name *search_service_blacklist(char *service_name, uint8_t service_name_len);
extern int check_if_intercept(uint32_t current_uid);
extern int intercept_all_apps(uint32_t current_uid);
extern uint8_t is_whitelist_empty;
extern uint32_t droidtracer_uid;
extern uint8_t appuid_counter;

// Note: global symbol "current" is currently scheduled process

/*
 * removes every second 0 from sequence of uint8_t
 */
void binder_data_tostr(const uint8_t *data_ptr, const uint8_t data_len, char *result)
{
  int i=0;
  for(; i<data_len; i++) {
    *(result + i) = (char) *(data_ptr + 2*i);
  }	  
  *(result + data_len) = 0;
}

/*
 * common handler for sys_read() and sys_write(), as function have same signature
 */
long handle_read_write(unsigned int fd, const char __user *buf,
	   size_t count, bool write) {
  struct timespec ts;
  char *buf_tmp;  
  //int i;

  /* only monitor apps in list apps_uid_to_monitor  */
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  }
  
  // buf  
  buf_tmp = kmalloc(count, GFP_KERNEL);
  if (copy_from_user(buf_tmp, buf, count))
    goto out;
  getnstimeofday(&ts);
    
  if(write) {
    D(printk("RV; sys_write; uid = %d, fd = %d, count = %zd, buf=", current->cred->uid, fd, count));
    N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, count, buf_tmp, "do_write"));
  } else {
    D(printk("RV; sys_read; uid = %d, fd = %d, count = %zd, buf=", current->cred->uid, fd, count));
    N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, count, buf_tmp, "do_read"));
  }

#ifdef DEBUG_ON
  for(i = 0; i < count; i++)
    printk("%c", buf_tmp[i]);
  printk("\n");
#endif

 out:
  kfree(buf_tmp);
  jprobe_return();
  return 0;
}

// TODO: do_read instead of sys_read?
long trace_sys_read(unsigned int fd, char __user *buf, size_t count) {
  return handle_read_write(fd, buf, count, false);  
}

// TODO: do_read instead of sys_write?
long trace_sys_write(unsigned int fd, const char __user *buf,
		      size_t count) {
  return handle_read_write(fd, buf, count, true);
}

/**
 * sys_send - only when the socket is in a connected state; calls sys_sendto with NUL address in net/socket.c
 * Also sys_send is equivalent to write, just different flags
 * sys_sendto - is for UDP, destination specified each time
 * sys_sendmsg - is the only necessary call, as send and sendto are just a wrapper
 */
//long sys_send(int, void __user *, size_t, unsigned) 

asmlinkage long trace_sys_sendto(int fd, void __user *buff, size_t len, unsigned flags,
	   struct sockaddr __user *addr, int addr_len) {
  struct timespec ts;
  char *buff_tmp;  
  int i;
  
  /* only monitor apps in list apps_uid_to_monitor  */
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  }

  printk("RV; sys_sendto; uid = %d\n", current->cred->uid);

  buff_tmp = kmalloc(len, GFP_KERNEL);
  if (copy_from_user(buff_tmp, buff, len))
    goto out;
  getnstimeofday(&ts);
  
  //#ifdef DEBUG_ON
  printk("RV; sys_sendto; uid = %d, fd = %d, len = %zd, buff=", current->cred->uid, fd, len);
  for(i = 0; i < len; i++)
    printk("%c", buff_tmp[i]);
  printk("\n");
  //#endif
  
  N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, len, buff_tmp, "sys_sendto"));
 
 out:
  kfree(buff_tmp);
  jprobe_return();
  return 0;
}


long handle_sendmsg_readmsg(int fd, struct msghdr __user * msg, unsigned int flags, bool send) {
  struct timespec ts;
  struct msghdr *msg_tmp;
  struct iovec *msg_iov_tmp;
  //void *iov_tmp;
  uint8_t *iov_tmp;
  int i;
  int j;

  /* only monitor apps in list apps_uid_to_monitor  */
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  }

  printk("RV; sys_sendmsg/recvmsg; uid=%d\n", current->cred->uid);

  msg_tmp = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
  if (copy_from_user(msg_tmp, msg, sizeof(struct msghdr)))
    goto out_msg;

  msg_iov_tmp = kmalloc(msg_tmp->msg_iovlen * sizeof(struct iovec), GFP_KERNEL);
  if (copy_from_user(msg_iov_tmp, msg_tmp->msg_iov, msg_tmp->msg_iovlen * sizeof(struct iovec))) {
    kfree(msg_iov_tmp);
    goto out_msg;
  }
  
  for(i = 0; i < msg_tmp->msg_iovlen; i++) {
 
    iov_tmp = kmalloc(msg_iov_tmp[i].iov_len, GFP_KERNEL);
    if (copy_from_user(iov_tmp, msg_iov_tmp[i].iov_base, msg_iov_tmp[i].iov_len)) {
      kfree(msg_iov_tmp);
      kfree(iov_tmp);
      goto out_msg;
    }
    getnstimeofday(&ts); 
      
    if(send) {
      printk("RV; sys_sendmsg; uid=%d, fd = %d, msg_iovlen=%d, iov_len=%d, iov=", current->cred->uid, fd, msg_tmp->msg_iovlen, msg_iov_tmp[i].iov_len);
      N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, msg_iov_tmp[i].iov_len, iov_tmp, "sys_sendmsg"));
    } else {
      printk("RV; sys_recvmsg; uid=%d, fd = %d, msg_iovlen=%d, iov_len=%d, iov=", current->cred->uid, fd, msg_tmp->msg_iovlen, msg_iov_tmp[i].iov_len);
      N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, msg_iov_tmp[i].iov_len, iov_tmp, "sys_recvmsg"));
    }
    //#ifdef DEBUG_ON   
      for(j = 0; j < msg_iov_tmp[i].iov_len; j++)
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


asmlinkage long trace_sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags) {
  return handle_sendmsg_readmsg(fd, msg, flags, true);      
}


/* recv() - only on a connected socket, identical to recvfrom() with a NULL src_addr argument
 * recvmsg() - equivalent to sendmsg()
 */
asmlinkage long trace_sys_recvmsg(int fd, struct msghdr __user * msg, unsigned int flags) {
  return handle_sendmsg_readmsg(fd, msg, flags, false);
}


/*
 * do_execve() is system-independent routine of sys_execve()
 * TODO intercept argv
 */
static int trace_do_execve(char *filename, char __user *__user *argv,
                char __user *__user *envp, struct pt_regs *regs)
{
  int ret;
  struct timespec ts;
  int i = 0;
  char *tmp;
  
  /* only monitor apps in list apps_uid_to_monitor  */
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  }
  
  printk("RV; do_execve; uid=%d\n", current->cred->uid);

  getnstimeofday(&ts);  

  // TODO argv
  
  // count how many arguments
  if (argv != NULL) {
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
      if(ret <= 0) {
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
  N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, strlen(filename), filename, "do_execve"));

 out:
  jprobe_return();
  return 0;
}

//  system-independent routine of sys_fork
long trace_do_fork(unsigned long clone_flags, unsigned long stack_start,
                struct pt_regs *regs, unsigned long stack_size,
                int __user *parent_tidptr, int __user *child_tidptr)
{
  struct timespec ts;

  /* only monitor apps in list apps_uid_to_monitor  */
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  }
  getnstimeofday(&ts);
  
  D(printk("RV; do_fork; parent_tidptr = 0x%p, child_tidptr = 0x%p,"
	 " pid = %d, uid = %d, euid = %d\n",
	 parent_tidptr, child_tidptr,
	   current->pid, current->cred->uid, (current->cred)->euid);)
  N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, 0, NULL, "do_fork"));

  jprobe_return();
  return 0;
}

asmlinkage long trace_sys_uselib(const char __user *library)
{
  char *library_tmp;  
  int ret;
  struct timespec ts;
  
  /* only monitor apps in list apps_uid_to_monitor  */
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  }
  
  printk("RV; sys_uselib; uid=%d\n", current->cred->uid);

  library_tmp = __getname();
  ret = strncpy_from_user(library_tmp, library, PATH_MAX + 1);
  if(ret <= 0) 
    goto out;
  getnstimeofday(&ts);
  
  printk("RV; sys_uselib; library = %s, uid = %d", library_tmp, current->pid);
  N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, strlen(library_tmp), library_tmp, "sys_uselib"));

 out:
  putname(library_tmp);
  jprobe_return();
  return 0;
}
 
 asmlinkage long trace_sys_open(const char __user *filename, int flags, int mode)
{  
  char *tmp;  
  int ret;
  struct timespec ts;

  /* only monitor apps in list apps_uid_to_monitor  */
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  } 

  printk("RV; sys_open; uid=%d\n", current->cred->uid);

  tmp = __getname();
  //tmp = kmalloc(PATH_MAX + 1, GFP_KERNEL);
  ret = strncpy_from_user(tmp, filename, PATH_MAX + 1);
  if(ret <= 0) {
    putname(tmp);
    jprobe_return();
    return 0;  
  }

  if (strstr(tmp, "/system/") == NULL && strstr(tmp, "/proc/") == NULL) {
  //if (strstr(tmp, "sdcard") != NULL || strstr(tmp, "/storage/emulated") != NULL) {
    // get time in sec since 1970 (epoch)
    getnstimeofday(&ts);
    
    N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, strlen(tmp), tmp, "sys_open"));	  
    printk("RV; sys_open; filename = %s, flags = 0x%x, mode=0o%03o, uid = %d.\n",
	   tmp, flags, mode, (current->cred)->uid);
  }
  
  putname(tmp);
  //kfree(tmp);
  jprobe_return();
  return 0;  
}


#ifndef socklen_t
typedef u_int32_t socklen_t;
#endif

static long trace_sys_connect(int sockfd, const struct sockaddr *addr,
			      socklen_t addrlen)
{
  struct timespec ts;
  struct sockaddr_in *ipv4;
  struct sockaddr_in6 *ipv6;

  /* only monitor apps in list apps_uid_to_monitor */  
  if(check_if_intercept(current->cred->uid)) {
    jprobe_return();
    return 0;
  }  

  printk("RV; sys_connect; uid=%d\n", current->cred->uid);

  // get time in sec since 1970 (epoch)
  getnstimeofday(&ts);
 
  if (addr->sa_family == AF_INET) {
    ipv4 = (struct sockaddr_in *) addr;
    //D(printk("RV; sys_connect, ipv4; fd = %d, ip = %u, uid = %d\n", sockfd, (ipv4->sin_addr).s_addr, (p->cred)->uid));
    D(printk("RV; sys_connect, ipv4; ip = %pI4, uid = %d\n", &ipv4->sin_addr.s_addr, current->cred->uid);)
    N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, sizeof(unsigned long), &ipv4->sin_addr.s_addr, "sys_connect"));	  
  } else if (addr->sa_family == AF_INET6) {
    // u_int8_t  s6_addr[16]; 128 bit
    ipv6 = (struct sockaddr_in6 *) addr;
    //D(printk("RV; sys_connect, ipv6; fd = %d, ip = %llu, uid = %d\n", sockfd, (ipv6->sin6_addr).s6_addr, current->cred->uid));
    D(printk("RV; sys_connect, ipv6; ip = %pI6, uid = %d\n", (ipv6->sin6_addr).s6_addr, current->cred->uid);)
    N(send_event(0,  current->cred->uid, (uint32_t) ts.tv_sec, 16, (uint8_t *) (ipv6->sin6_addr).s6_addr, "sys_connect"));	  
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
 * method "trace_binder_transaction" is not exported, thus cannot
 * monitored by jprobes
 */
int
trace_binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
                    void __user *buffer, int size, signed long *consumed)
{
  uint32_t cmd;
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;
  uint8_t is_appuid_monitored;
  char *service_name;
  //int i;
  //int j;
  //int k;
  //uint8_t *buffer_tmp;			
  //uint8_t *buffer_tmp2;			

  /* nerver monitor droidtracer itself */
  /* only continue if > 0 apps monitored */
  if(current->cred->uid == droidtracer_uid || appuid_counter == 0 /*(current->cred->uid != 1000 && current->cred->uid <= 10052) || appuid_counter == 0 || current->cred->uid == 10017 */) {
    jprobe_return();
    return 0;
  }    

  is_appuid_monitored = (search_appuid(current->cred->uid) != NULL);
  /* only monitor apps in list apps_uid_to_monitor */
  if(!is_appuid_monitored && !intercept_all_apps(current->cred->uid) && is_whitelist_empty) {
    jprobe_return();
    return 0;
  }  

  while (ptr < end && thread->return_error == BR_OK) {
    if (get_user(cmd, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
      binder_stats.bc[_IOC_NR(cmd)]++;
      proc->stats.bc[_IOC_NR(cmd)]++;
      thread->stats.bc[_IOC_NR(cmd)]++;
    }
    if (cmd == BC_TRANSACTION) { // || cmd == BC_REPLY      
      /* handle (target method Remote Interface)
       * sender_pid/euid is not copied from user space 
       * code (method ID)
       * data.ptr.buffer (Parcel - Input/Output Parameters)
       */         
      
      struct binder_transaction_data tr;
      if (copy_from_user(&tr, ptr, sizeof(tr)))
	return -EFAULT;

      if(tr.data_size > 4) {
	// get service name
	const uint8_t *data_ptr = tr.data.ptr.buffer;
	//const uint8_t *offsets_ptr = tr.data.ptr.offsets;
	const uint8_t *service_name_len_ptr = data_ptr + 4;
	const uint8_t *service_name_ptr = service_name_len_ptr + 4;

	// get time in sec since 1970 (epoch)
	struct timespec ts;
	getnstimeofday(&ts);
	
	service_name = kmalloc((*service_name_len_ptr)+1, GFP_KERNEL);
	if(!service_name)
	  D(printk("RV; cannot allocate memory for service_name.\n"));	  
	binder_data_tostr(service_name_ptr, *service_name_len_ptr, service_name);
	D(printk("RV; to check service_name=%s, len=%d\n", service_name, (*service_name_len_ptr)+1));  
	
	/* do NOT monitor services in blacklist, but those in whitelist */
	if(search_service_len_blacklist((*service_name_len_ptr)+1) != NULL) {
  
	  /*
	  char *service_name;
	  service_name = kmalloc((*service_name_len_ptr)+1, GFP_KERNEL);
	  if(!service_name)
	    D(printk("RV; cannot allocate memory for service_name.\n"));	  
	  binder_data_tostr(service_name_ptr, *service_name_len_ptr, service_name);
	  printk("RV; to check service_name=%s, len=%d\n", service_name, (*service_name_len_ptr)+1);  
	  */

	  struct rbnode_service_name *service_name_node = search_service_blacklist(service_name, (*service_name_len_ptr)+1);
	  if(service_name_node != NULL) {
	    /* service in black or white list */

	    //D(printk("RV; ignored service_name=%s, len=%d\n", service_name, (*service_name_len_ptr)+1));
	    if(service_name_node->is_in_whitelist) {
	      /* entry is in whitelist */
	      
	    } else {
	      /* entry is in blacklist */
	      kfree(service_name);	 
	      jprobe_return();
	      return 0;
	    }
	  } else if(!is_appuid_monitored && !intercept_all_apps(current->cred->uid)) {
	    kfree(service_name);	 
	    jprobe_return();
	    return 0;
	  }	  	  
	  kfree(service_name);
	 
	} else if(!is_appuid_monitored && !intercept_all_apps(current->cred->uid)) {
	  kfree(service_name);	 
	  jprobe_return();
	  return 0;
	}
	
	/*
	if (strstr(service_name, "android.app.IActivityManager") != NULL) {
	  D(printk("RV; serv_name=%s\n", service_name));
	  D(printk("RV; code=%d\n", tr.code));
	  D(printk("RV; flags=%d\n", tr.flags));
	  D(printk("RV; sender_pid=%d\n", tr.sender_pid));
	  D(printk("RV; sender_euid=%d\n", tr.sender_euid));
	  D(printk("RV; data_size=%d\n", tr.data_size));
	  D(printk("RV; offsets_size=%d\n", tr.offsets_size));
	}
	*/

	//printk("RV; time=%ld, app_uid=%d, method_id=%d, serv_name=%s", ts.tv_sec, current->cred->uid, tr.code, service_name);
	D(printk("RV; time=%ld, app_uid=%d, method_id=%d\n", ts.tv_sec, current->cred->uid, tr.code));
	N(send_event((uint8_t) tr.code,  current->cred->uid, (uint32_t) ts.tv_sec, tr.data_size, tr.data.ptr.buffer, NULL));	  

	#ifdef DEBUG_ON
	// TODO intercept offsets, to get flat_binder_object, i.e.,
	// objects transferred through writeStrongBinder()
	if(tr.offsets_size > 0)
	  printk("RV; offsets_size=%d, offset=", tr.offsets_size);
	for(k = 0; k<tr.offsets_size; k++) {
	  printk("%d", *offsets_ptr);
	  offsets_ptr++;
	}
	printk("\n");

	/* print tr.data.ptr.buffer (after service name) as string */
	buffer_tmp = (uint8_t *) data_ptr;
	//buffer_tmp = service_name_ptr + 2*(*service_name_len_ptr);
	printk(", buf_param_string=");
	for(i = 0; i<tr.data_size; i++) {
	  printk("%c", *buffer_tmp);
	  buffer_tmp++;
	}
	    
	/* print tr.data.ptr.buffer (after service name) as uint8_t */
	printk(", buf_uint8_t=");
	//buffer_tmp2 = (uint8_t *) data_ptr;
	//buffer_tmp2 = service_name_ptr + 2*(*service_name_len_ptr);
	buffer_tmp2 = data_ptr;	    

	for(j = 0; j<tr.data_size; j++) {
	  printk("%d ", *buffer_tmp2);
	  buffer_tmp2++;
	}
	printk("\n");
	#endif
	//}
      } else {
	// tr.data_size <= 4
	D(printk("RV; not known BC_TRANSACTION.\n"));
      }
    }
  }
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

#define CREATE_JPROBE(victim, target) \
        static struct jprobe jp_##victim = { \
                .entry = (kprobe_opcode_t *) target, \
                .kp = { \
                        .symbol_name = #victim, \
                }, \
        }

CREATE_JPROBE(do_execve, trace_do_execve);
//CREATE_JPROBE(sys_sendto, trace_sys_sendto);
//CREATE_JPROBE(sys_sendmsg, trace_sys_sendmsg);
//CREATE_JPROBE(sys_recvmsg, trace_sys_recvmsg);
//CREATE_JPROBE(do_fork, trace_do_fork);
//CREATE_JPROBE(sys_read, trace_sys_read);
//CREATE_JPROBE(sys_write, trace_sys_write);
CREATE_JPROBE(sys_open, trace_sys_open);
CREATE_JPROBE(sys_uselib, trace_sys_uselib);
CREATE_JPROBE(sys_connect, trace_sys_connect);
CREATE_JPROBE(binder_thread_write, trace_binder_thread_write);
//CREATE_JPROBE(sys_socket, trace_sys_socket);


// Note: prefix of jprobe objects is defined as jp_ in CREATE_JPROBE
#define NUM_PROBES 5
static struct jprobe *jprobes[NUM_PROBES] = {
  &jp_do_execve,
  //&jp_sys_sendto,
  //&jp_sys_sendmsg,  
  //&jp_sys_recvmsg,
  //&jp_do_fork,
  //&jp_sys_read,
  //&jp_sys_write,
  &jp_sys_open,
  &jp_sys_connect,
  &jp_sys_uselib,
  &jp_binder_thread_write
  //&jp_sys_socket
};



int init_module(void)
{
  int ret; 

  /* plant jprobes */  
  // returns 0 on success, or a negative errno otherwise
  ret = register_jprobes(jprobes, NUM_PROBES);
  if (ret < 0) {
    D(printk("RV; register_jprobes failed, returned value: %d\n", ret));
    return ret;
  }
  printk("RV; planted %d jprobes\n", NUM_PROBES);  

  /* start netlink communication */
  if(init_netlink()) {
    return 1;
  }

  return 0;
}

void cleanup_module(void)
{
  unregister_jprobes(jprobes, NUM_PROBES);
  printk("RV; jprobes unregistered\n");

  /* stop netlink communication */
  exit_netlink();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jan-Christoph Kuester");
