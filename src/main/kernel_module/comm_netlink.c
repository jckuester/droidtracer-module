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

#include <net/genetlink.h>
#include <linux/module.h>
#define __NO_VERSION__
#include <linux/kernel.h>
#include <linux/kmod.h>
#include "comm_netlink.h"

static int insert_appuid(uint32_t appuid);
static int insert_service_len_blacklist(uint8_t service_name_len);
static int delete_appuid(uint32_t appuid);
static int cb_delete_app(struct sk_buff *skb_2, struct genl_info *info);
static int cb_intercept_all_apps(struct sk_buff *skb_2, struct genl_info *info);
static int cb_set_droidtracer_uid(struct sk_buff *skb_2, struct genl_info *info);
static int cb_add_service_whitelist(struct sk_buff *skb_2, struct genl_info *info);
static int cb_add_app(struct sk_buff *skb_2, struct genl_info *info);
static int cb_add_service_blacklist(struct sk_buff *skb_2, struct genl_info *info);
static int insert_service_blacklist(char *service_name, uint8_t service_len, uint8_t is_in_whitelist);

/* PID of the droidertracer service (living in java land) */
uint32_t pid = -1;
uint32_t droidtracer_uid = -1;
// track every event sent to user space
uint32_t seq_id = 1;
extern int lowest_uid_traced;

/* flag that indicates if all apps should be monitored */

uint8_t is_whitelist_empty = true;
uint8_t appuid_counter = 0;

/* family definition */
struct genl_family droidtracer_family = {
	//generic netlink controller assigns channel number for us
	.id = GENL_ID_GENERATE,        
	.hdrsize = 0,
	//the name of this new family we register
	.name = "DROIDTRACER",        
	.version = VERSION_NR,                   
	.maxattr = ATTR_MAX,
};

/* attribute policy: defines which attribute has which type (e.g int, char * etc)
 * possible values defined in net/netlink.h 
 */
static struct nla_policy policy[ATTR_MAX + 1] = {
	[TIME] = { .type = NLA_U32 },
	[CODE] = { .type = NLA_U8 },
	// send void* 
	[PARCEL] = { .type = NLA_UNSPEC}, 
	[UID] = { .type = NLA_U32 },
	[SERVICE] = { .type = NLA_STRING }
};

/* nodes for rbtree
   each contains UID of app to monitor */
struct rbnode_appuid {
	struct rb_node node;
	uint32_t appuid;
};

/* nodes for rbtree
   contains all service iface names with same length */
struct rbnode_services_len {
	struct rb_node node_service_len;
	uint8_t len;
	struct rb_root rbroot_services_name;
};

/*
 * self-balanced binary tree vs. hashmap
 * average complexity: O(log n) vs. O(1)
 * worst case complexity: O(log n) vs. O(n)
 */
static struct rb_root rbroot_appuid = RB_ROOT;

/*
 * service interfaces that are not monitored
 */
static struct rb_root rbroot_services_blacklist = RB_ROOT;

int check_if_intercept(uint32_t current_uid) {
	if (search_appuid(current_uid) == NULL &&
			lowest_uid_traced >= current_uid)
		return true;
	else
		return false;
}

struct rbnode_appuid *search_appuid(uint32_t appuid)
{
	struct rb_node *node = rbroot_appuid.rb_node;
	struct rbnode_appuid *data;
  
	while (node) {
		data = rb_entry(node, struct rbnode_appuid, node); 
		
		if (appuid < data->appuid)
			node = node->rb_left;
		else if (appuid > data->appuid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

struct rbnode_services_len *search_service_len_blacklist(uint8_t service_name_len)
{
	struct rb_node *node = rbroot_services_blacklist.rb_node;
	struct rbnode_services_len *data;
	
	//printk("RV; bla len=%d\n", service_name_len);
	
	while (node) {
		data = rb_entry(node, struct rbnode_services_len, node_service_len); 
		
		if (service_name_len < data->len)
			node = node->rb_left;
		else if (service_name_len > data->len)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}


struct rbnode_service_name *search_service_blacklist(char *service_name, uint8_t service_name_len)
{
	struct rb_node *node = search_service_len_blacklist(service_name_len)->rbroot_services_name.rb_node;
	struct rbnode_service_name *data;
	
	//printk("RV; bla service=%s, len=%d\n", service_name, service_name_len);
	if (node == NULL)
		return NULL;
	
	while (node) {
		data = rb_entry(node, struct rbnode_service_name, node_service_name); 
		
		if (strcmp(service_name, data->name) < 0)
			node = node->rb_left;
		else if (strcmp(service_name, data->name) > 0)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

/*
  http://man7.org/linux/man-pages/man7/netlink.7.html
  
  Netlink  is  not a reliable protocol.  It tries its best to deliver a
  message to its destination(s), but may drop messages when an  out-of-
  memory  condition  or  other error occurs.  For reliable transfer the
  sender can request an acknowledgement from the  receiver  by  setting
  the  NLM_F_ACK flag.  An acknowledgment is an NLMSG_ERROR packet with
  the  error  field  set  to  0.    The   application   must   generate
  acknowledgements  for  received messages itself.  The kernel tries to
  send an NLMSG_ERROR message for every failed packet.  A user  process
  should follow this convention too.
  
  However, reliable transmissions from kernel to user are impossible in
  any case.  The kernel can't send a  netlink  message  if  the  socket
  buffer  is  full:  the message will be dropped and the kernel and the
  user-space process will no longer have the same view of kernel state.
  It  is  up  to  the  application to detect when this happens (via the
  ENOBUFS error returned by recvmsg(2)) and resynchronize.  

  char *sys_call: only used for kernel handled method calls (sys_connect->internet,
  sys_open->sdcard, ...)
*/
int send_event(uint8_t method_id, uint32_t app_uid, 
	       uint32_t time, int data_size, const void *data, char *sys_call) 
{
	struct sk_buff *skb;
	void *msg_head;
	int rc; 
	
	if (pid < 0) {
		printk("RV; Error: cannot send event, wrong pid of java-monitor\n");
		return 1;
	}
	
	/* send a message back*/
	/* allocate some memory, since the size is not yet known use NLMSG_GOODSIZE*/	
	/* do not free, genlmsg_unicast takes care, because message can be
	   stuck in the queue for a while */
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		goto out;
	
	/* create the message headers */
	/* arguments of genlmsg_put: 
	   struct sk_buff *, 
	   int (sending) pid, 
	   int sequence number, 
	   struct genl_family *, 
	   int flags, 
	   u8 command index (why do we need this?)
	*/
	// TODO NL_AUTO_PORT, NL_AUTO_SEQ
	// msg_head = genlmsg_put(skb, 0, 0, &doc_exmpl_gnl_family, 0, ADD_APP_TO_MONITOR);
	msg_head = genlmsg_put(skb, 0, seq_id++, &droidtracer_family, 0, (int) NULL);
	
	if (msg_head == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	
	/* add attributes (actual values to be sent) */
	if (sys_call != NULL) {
		rc = nla_put_string(skb, SERVICE, sys_call);
		if (rc != 0)
			goto out;
	}
	rc = nla_put_u8(skb, CODE, method_id);
	if (rc != 0)
		goto out;
	rc = nla_put_u32(skb, UID, app_uid);
	if (rc != 0)
		goto out;
	rc = nla_put_u32(skb, TIME, time);
	if (rc != 0)
		goto out;
	if (data != NULL) {
		rc = nla_put(skb, PARCEL, data_size, data);
		if (rc != 0)
			goto out;    
	}
	
	/* finalize the message */
	genlmsg_end(skb, msg_head);
	
	/* send the message back */
	// for ARM (what is init_net???)
#ifdef ARM
	rc = genlmsg_unicast(&init_net, skb, pid);
	// for goldfish 
#elif defined GOLDFISH
	rc = genlmsg_unicast(skb, pid);
#endif
	if (rc != 0)
		goto out;
	
	D(printk("RV; event sent to java-app with pid=%zu\n", pid));
	return 0;
	
 out:
	
	// http://stackoverflow.com/questions/15676667/how-to-execute-shell-command-in-kernel-programming
	/* static char *envp[] =  {  */
	/*   "HOME=/",  */
	/*   "PATH=/sbin:/system/sbin:/system/bin:/system/xbin", NULL }; */
	/* char *argv[] = { "/system/bin/am", "start", "-a", "android.intent.action.MAIN",   */
	/* 		 "-n", "com.monitorme/.MainActivity",  NULL}; */
	/* /\* */
	/* char * argv[] = { "/system/bin/am", */
	/* 		    "startservice", */
	/* 		    "-a", */
	/* 		    "com.droidtracer.DroidTracerService", NULL }; */
	/* *\/ */
	/* rc = call_usermodehelper(argv[0], argv, envp, /\* UMH_WAIT_PROC *\/ UMH_WAIT_EXEC /\* 1 *\/); */
	/* if (rc != 0) */
	/*   printk("RV; cannot start DroidTracerService\n"); */
	
	// TODO triggers anyway?
	//printk("RV; an error occured in netlink communication.\n");
	
	return 0;
}

static int cb_add_app(struct sk_buff *skb_2, struct genl_info *info)  
{
	struct nlattr *na;
	uint32_t appuid;
	
	if (info == NULL)
		printk("RV; an error occured in cb_add_app.\n");
	
	pid = info->snd_pid;
	
	/*for each attribute there is an index in info->attrs which points to a nlattr structure
	 *in this structure the data is given
	 */
	na = info->attrs[UID];
	if (na) {
		appuid = (uint32_t) nla_get_u32(na);
		if (appuid == 0)
			printk("RV; error while receiving data\n");
		else {      
			/* add appuid to rbtree */
			if (insert_appuid(appuid)) {
				printk("RV; start monitoring app with uid=%zu\n", appuid);
			} else {
				printk("RV; app with uid=%zu is already monitored\n", appuid);
			}      
		}  
	} else {
		printk("RV; no attr UID info->attrs=%i\n", UID);
	}
	
	return 0;
}

/* 
 * register the operations for the family, i.e., 
 * define what function handles which command
 */
int droidtracer_register_genl_ops(void)
{
	int ret;
	
	/* define mappings between the command identifier
	   and the actual handler */
	static struct genl_ops ops_add_app = {
		/* command */
		.cmd = ADD_APP,
		.flags = 0,
		.policy = policy,
		/* function that handles the received command */
		.doit = cb_add_app,
		.dumpit = NULL,
	};
	static struct genl_ops ops_delete_app = {
		.cmd = DELETE_APP,
		.flags = 0,
		.policy = policy,
		.doit = cb_delete_app,
		.dumpit = NULL,
	};
	static struct genl_ops ops_add_service_blacklist = {
		.cmd = ADD_SERVICE_BLACKLIST,
		.flags = 0,
		.policy = policy,
		.doit = cb_add_service_blacklist,
		.dumpit = NULL,
	};
	static struct genl_ops ops_add_service_whitelist = {
		.cmd = ADD_SERVICE_WHITELIST,
		.flags = 0,
		.policy = policy,
		.doit = cb_add_service_whitelist,
		.dumpit = NULL,
	};
	static struct genl_ops ops_set_droidtracer_uid = {
		.cmd = SET_DROIDTRACER_UID,
		.flags = 0,
		.policy = policy,
		.doit = cb_set_droidtracer_uid,
		.dumpit = NULL,
	};
	static struct genl_ops ops_intercept_all_apps = {
		.cmd = INTERCEPT_ALL_APPS,
		.flags = 0,
		.policy = policy,
		.doit = cb_intercept_all_apps,
		.dumpit = NULL,
	};

	/* register operations for the family */
	ret = genl_register_ops(&droidtracer_family, &ops_add_app);
	if (ret < 0)
		goto err;

	ret = genl_register_ops(&droidtracer_family, &ops_delete_app);
	if (ret < 0)
		goto err;

	ret = genl_register_ops(&droidtracer_family, &ops_add_service_blacklist);
	if (ret < 0)
		goto err;
	
	ret = genl_register_ops(&droidtracer_family, &ops_add_service_whitelist);
	if (ret < 0)
		goto err;
    
	ret = genl_register_ops(&droidtracer_family, &ops_set_droidtracer_uid);
	if (ret < 0)
		goto err;

	ret = genl_register_ops(&droidtracer_family, &ops_intercept_all_apps);
	if (ret < 0)
		goto err;
	
	return 0;
 err:
	printk(KERN_ERR "RV; failed to register operation = %i\n", ret);
	/* unregister the family 
	   note: all assigned operations are unregistered automatically */
	genl_unregister_family(&droidtracer_family);
	return -1;
}

static int cb_add_service_blacklist(struct sk_buff *skb_2, struct genl_info *info)  
{
	struct nlattr *na;
	char *service_name;
	
	pid = info->snd_pid;
	
	if (info == NULL)
		printk("RV; an error occured in cb_add_service_blacklist.\n");
	
	/*for each attribute there is an index in info->attrs which points to a nlattr structure
	 *in this structure the data is given
	 */
	na = info->attrs[SERVICE];
	if (na) {
		// nla_len(na) is length of null terminated string
		service_name = kmalloc(nla_len(na), GFP_KERNEL);
		nla_strlcpy(service_name, na, nla_len(na));
		//printk("RV; added service_name=%s, len=%d\n", service_name, nla_len(na));
		if (service_name == NULL)
			printk("RV; error while receiving data\n");
		else {      
			/* add appuid to rbtree */    
			if (insert_service_blacklist(service_name, nla_len(na), false)) {
				printk("RV; added service=%s to blacklist\n", service_name);
			} else {
				printk("RV; service=%s is already on blacklist\n", service_name);
			}  
			
		}  
	} else {
		printk("RV; no attr SERVICE info->attrs=%i\n", SERVICE);
	}
	
	return 0;
}

static int cb_add_service_whitelist(struct sk_buff *skb_2, struct genl_info *info)  
{
	struct nlattr *na;
	char *service_name;
	
	pid = info->snd_pid;
	
	if (info == NULL)
		printk("RV; an error occured in cb_add_service_whitelist.\n");
	
	/*for each attribute there is an index in info->attrs which points to a nlattr structure
	 *in this structure the data is given
	 */
	na = info->attrs[SERVICE];
	if (na) {
		// nla_len(na) is length of null terminated string
		service_name = kmalloc(nla_len(na), GFP_KERNEL);
		nla_strlcpy(service_name, na, nla_len(na));
		//printk("RV; added service_name=%s, len=%d\n", service_name, nla_len(na));
		if (service_name == NULL)
			printk("RV; error while receiving data\n");
		else {      
			/* add appuid to rbtree */    
			if (insert_service_blacklist(service_name, nla_len(na), true)) {
				printk("RV; added service=%s to whitelist\n", service_name);
			} else {
				printk("RV; service=%s is already on whitelist\n", service_name);
			}  
			
		}  
	} else {
		printk("RV; no attr SERVICE info->attrs=%i\n", SERVICE);
	}
	
	return 0;
}

static int cb_set_droidtracer_uid(struct sk_buff *skb_2, struct genl_info *info)  
{
	struct nlattr *na;
	uint32_t uid;
	
  if (info == NULL)
	  printk("RV; an error occured in cb_set_droidtracer_uid.\n");
  
  /* TODO set pid only the first time function is called */
  pid = info->snd_pid;
  
  na = info->attrs[UID];
  if (na) {	  
	  uid = (uint32_t) nla_get_u32(na);
	  if (uid) {
		  // set droidtracer uid
		  droidtracer_uid = uid;
		  //intercept_all_apps_flag = true;    
		  printk("RV; set droidtracer uid=%d.\n", uid);
	  }   
  } else {
	  printk("RV; no attr SERVICE info->attrs=%i\n", SERVICE);
  }  
  return 0;
}

static int cb_intercept_all_apps(struct sk_buff *skb_2, struct genl_info *info)  
{
	struct nlattr *na;
	uint32_t uid;
	
	if (info == NULL)
		printk("RV; an error occured in cb_intercept_all_apps.\n");
	
	/* TODO set pid only the first time function is called */
	pid = info->snd_pid;
	
	na = info->attrs[UID];
	if (na) {		
		uid = (uint32_t) nla_get_u32(na);
		if (uid) {
			// set droidtracer uid
			droidtracer_uid = uid;
			//intercept_all_apps_flag = true;    
			printk("RV; intercepting all apps enabled.\n");
		} else {
			// if you user sends 0 (instead of real droidtracer uid) means false
			//intercept_all_apps_flag = false;
			printk("RV; intercepting all apps disabled.\n");
		}   
	} else {
		printk("RV; no attr SERVICE info->attrs=%i\n", SERVICE);
	}	
	return 0;
}

/*
 * callback method to delete app
 */
static int cb_delete_app(struct sk_buff *skb_2, struct genl_info *info)  
{
	struct nlattr *na;
	uint32_t appuid;
	
	if (info == NULL)
		printk("RV; an error occured in cb_delete_app.\n");
	
	pid = info->snd_pid;
	
	/*for each attribute there is an index in info->attrs which points to a nlattr structure
	 *in this structure the data is given
	 */
	na = info->attrs[UID];
	if (na) {
		appuid = (uint32_t) nla_get_u32(na);
		if (appuid == 0)
			printk("RV; error while receiving data\n");
		else {      
			/* delete appuid from rbtree */
			if (delete_appuid(appuid)) {
				printk("RV; stop monitoring app with uid=%zu\n", appuid);
			} else {
				printk("RV; app with uid=%zu is not monitored\n", appuid);
			}      
		}  
	} else {
		printk("RV; no info->attrs %i\n", UID);
	}	
	return 0;
}

static int insert_appuid(uint32_t appuid)
{
	struct rb_node **new = &(rbroot_appuid.rb_node), *parent = NULL;
	struct rbnode_appuid *data;
	struct rbnode_appuid *this;
	
	/* Figure out where to put new node */
	while (*new) {
		//this = container_of(*new, struct rbnode_appuid, node);
		this = rb_entry(*new, struct rbnode_appuid, node);
		parent = *new;
		
		if (appuid < this->appuid)
			new = &((*new)->rb_left);
		else if (appuid > this->appuid)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	data = kzalloc(sizeof(struct rbnode_appuid), GFP_KERNEL);
	
	if (!data)
		printk("RV; Error: cannot allocate memory for appuid=%d", appuid);  
	
	data->appuid = appuid;
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &rbroot_appuid);
  
	appuid_counter++;
	return true;
}

static int insert_service_len_blacklist(uint8_t service_name_len)
{
	struct rb_node **new = &(rbroot_services_blacklist.rb_node), *parent = NULL;
	struct rbnode_services_len *data;
	struct rbnode_services_len *this;
	
	/* Figure out where to put new node */
	while (*new) {
		this = rb_entry(*new, struct rbnode_services_len, node_service_len);
		parent = *new;
	  
		if (service_name_len < this->len)
			new = &((*new)->rb_left);
		else if (service_name_len > this->len) 
			new = &((*new)->rb_right);
		else 
			return false;    
	}
	
	/* Add new node and rebalance tree. */
	data = kzalloc(sizeof(struct rbnode_services_len), GFP_KERNEL);
  
	if (!data)
		printk("RV; Error: cannot allocate memory for service_name_len node=%d", service_name_len);  
	
	data->len = service_name_len;
	data->rbroot_services_name = RB_ROOT;
	rb_link_node(&data->node_service_len, parent, new);
	rb_insert_color(&data->node_service_len, &rbroot_services_blacklist);
	
	return true;
}

static int insert_service_blacklist(char *service_name, uint8_t service_len, uint8_t is_in_whitelist)
{
	struct rb_node **new = NULL, *parent = NULL;
	struct rbnode_service_name *data;
	struct rbnode_service_name *this;
	
	insert_service_len_blacklist(service_len);
	new = &(search_service_len_blacklist(service_len)->rbroot_services_name.rb_node);
	
	/* Figure out where to put new node */
	while (*new) {
		//this = container_of(*new, struct rbnode_appuid, node);
		this = rb_entry(*new, struct rbnode_service_name, node_service_name);
		parent = *new;
		
		if (strcmp(service_name, this->name) < 0)
			new = &((*new)->rb_left);
		else if (strcmp(service_name, this->name) > 0)
			new = &((*new)->rb_right);
		else
			return false;
  }

	/* Add new node and rebalance tree. */
	data = kzalloc(sizeof(struct rbnode_service_name), GFP_KERNEL);

	if (!data)
		printk("RV; Error: cannot allocate memory for service_name node=%s", service_name);

	data->name = service_name;
	if (is_in_whitelist) {
		is_whitelist_empty = false;
		data->is_in_whitelist = true;
	} else {
		data->is_in_whitelist = false;
	}
	rb_link_node(&data->node_service_name, parent, new);
	rb_insert_color(&data->node_service_name, &search_service_len_blacklist(service_len)->rbroot_services_name);
	
	return true;
}

static int delete_appuid(uint32_t appuid) {
	struct rbnode_appuid *data = search_appuid(appuid);

	if (data) {
		rb_erase(&data->node, &rbroot_appuid);
		kfree(data);

		appuid_counter--;
		return true;
	}
	return false;
}
