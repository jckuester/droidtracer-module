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

#include <linux/module.h>
#define __NO_VERSION__
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <net/genetlink.h>
#include <linux/rbtree.h>
#include <linux/cred.h>

#include "genl-endpoint.h"

static int cb_trace_app(struct sk_buff *, struct genl_info *);
static int cb_untrace_app(struct sk_buff *, struct genl_info *);
static int cb_whitelist_interface(struct sk_buff *, struct genl_info *);
static int cb_remove_whitelist_interface(struct sk_buff *, struct genl_info *);
static int cb_blacklist_interface(struct sk_buff *, struct genl_info *);
static int cb_remove_blacklist_interface(struct sk_buff *, struct genl_info *);
static int cb_set_lowest_uid_traced(struct sk_buff *, struct genl_info *);
static int cb_set_droidtracer_uid(struct sk_buff *, struct genl_info *);
static int insert_interface_len(uint8_t iface_len);
static int blacklist_iface(char *iface, uint8_t iface_len, uint8_t whitelist);
static int untrace_appuid(uid_t uid);

/* PID of the droidertracer service
   (living in java land) */
static pid_t droidtracer_service_pid = -1;
uid_t droidtracer_uid = -1;
/* track every event sent to user space */
uint32_t seq_id = 1;
extern int lowest_uid_traced;
uint8_t whitelist_empty = true;
uint8_t appuid_counter = 0;

/* family definition */
struct genl_family droidtracer_family = {
	/* generic netlink controller assigns
	   channel number for us */
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	/* name of new family we register */
	.name = FAMILY_NAME,
	.version = VERSION_NR,
	.maxattr = ATTR_MAX,
};

/*
 * defines which attribute has which type
 * possible values defined in net/netlink.h
 */
struct nla_policy policy[ATTR_MAX + 1] = {
	[TIME] = { .type = NLA_U32 },
	[CODE] = { .type = NLA_U8 },
	[PARCEL] = { .type = NLA_UNSPEC},
	[UID] = { .type = NLA_U32 },
	[SERVICE] = { .type = NLA_STRING }
};

/* each node for rbtree
   contains UID of app to trace */
struct rbnode_uid {
	struct rb_node node;
	uid_t uid;
};

/* nodes contains all
   interfaces with same length */
struct rbnode_iface_len {
	struct rb_node node;
	uint8_t len;
	struct rb_root rbroot_ifaces;
};

/*
 * self-balanced binary tree vs. hashmap
 * average complexity: O(log n) vs. O(1)
 * worst case complexity: O(log n) vs. O(n)
 */
static struct rb_root rbroot_appuids_traced = RB_ROOT;
static struct rb_root rbroot_filtered_interfaces = RB_ROOT;

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

  char *sys_call: only used for kernel handled method calls
  (sys_connect->internet, sys_open->sdcard, ...)
*/
int send_event(uint8_t code, uid_t appuid, uint32_t time, int data_size,
	const void *data, char *syscall)
{
	struct sk_buff *skb;
	void *msg_head;
	int err = -1;

	if (droidtracer_service_pid < 0 && printk_ratelimit()) {
		printk(KERN_WARNING
				"RV; PID of droidtracer service unset\n");
		return -1;
	}

	/* send a message back
	 * allocate some memory, since size is not known yet use NLMSG_GOODSIZE
	 * do not free, genlmsg_unicast takes care, because message can be
	 * stuck in the queue for a while
	 *
	 * FIXME: GFP_ATOMIC?
	 */
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOWAIT);
	if (!skb)
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
	// msg_head = genlmsg_put(skb, 0, 0, ...);
	msg_head = genlmsg_put(skb, 0, seq_id++,
			&droidtracer_family, 0, (int) NULL);
	if (!msg_head) {
		err = -ENOMEM;
		goto out;
	}

	/* add attributes (actual values to be sent) */
	if (syscall) {
		err = nla_put_string(skb, SERVICE, syscall);
		if (err)
			goto out;
	}
	err = nla_put_u8(skb, CODE, code);
	if (err)
		goto out;
	err = nla_put_u32(skb, UID, appuid);
	if (err)
		goto out;
	err = nla_put_u32(skb, TIME, time);
	if (err)
		goto out;
	if (data) {
		err = nla_put(skb, PARCEL, data_size, data);
		if (err)
			goto out;
	}

	/* finalize the message */
	genlmsg_end(skb, msg_head);

	/* send the message back */
#ifdef ARM
	/* what is init_net??? */
	err = genlmsg_unicast(&init_net, skb, droidtracer_service_pid);
#elif defined GOLDFISH
	err = genlmsg_unicast(skb, droidtracer_service_pid);
#endif
	if (err) {
		printk(KERN_ERR "RV; failed to send genl message: %d\n", err);
		return err;
	}
	return 0;

 out:
	printk(KERN_ERR "RV; failed to create netlink message: %d\n", err);
	return err;
}

/*
 * check if uid needs to be traced
 */
int intercept(uid_t uid) {
	if(uid == droidtracer_uid)
		return false;

	if (get_appuid(uid) ||
		uid >= lowest_uid_traced)
		return true;

	return false;
}

struct rbnode_uid *get_appuid(uid_t uid)
{
	struct rb_node *node = rbroot_appuids_traced.rb_node;
	struct rbnode_uid *data;

	while (node) {
		data = rb_entry(node, struct rbnode_uid, node);

		if (uid < data->uid)
			node = node->rb_left;
		else if (uid > data->uid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

struct rbnode_iface_len *get_blacklisted_iface_len(uint8_t iface_len)
{
	struct rb_node *node = rbroot_filtered_interfaces.rb_node;
	struct rbnode_iface_len *data;

	while (node) {
		data = rb_entry(node, struct rbnode_iface_len, node);

		if (iface_len < data->len)
			node = node->rb_left;
		else if (iface_len > data->len)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

struct rbnode_interface *get_blacklisted_iface(char *iface, uint8_t iface_len)
{
	struct rb_node *node =
		get_blacklisted_iface_len(iface_len)->rbroot_ifaces.rb_node;
	struct rbnode_interface *data;

	if (!node)
		return NULL;

	while (node) {
		data = rb_entry(node, struct rbnode_interface, node);

		if (strcmp(iface, data->name) < 0)
			node = node->rb_left;
		else if (strcmp(iface, data->name) > 0)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static int cb_trace_app(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	uid_t uid;

	if (!info)
		goto out;

	/*
	 * for each attribute there is an index in info->attrs which points
	 * to a nlattr structure in this structure the data is given
	 */
	na = info->attrs[UID];
	if (na) {
		uid = (uid_t) nla_get_u32(na);
		if (uid < 0) {
			printk("RV; cannot trace app with UID %d\n", uid);
			goto out;
		}

		if (trace_appuid(uid))
			printk("RV; start tracing app with uid=%zu\n", uid);
		else
			printk("RV; app with uid=%zu already traced\n", uid);

		return 0;
	}
	printk("RV; no attr UID info->attrs=%i\n", UID);

out:
	printk("RV; an error occured in cb_trace_app\n");
	return -1;
}

static int cb_untrace_app(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	uid_t uid;

	if (!info)
		printk("RV; an error occured in cb_untrace_app\n");

	na = info->attrs[UID];
	if (na) {
		uid = (uid_t) nla_get_u32(na);
		if (uid <= 0) {
			printk(KERN_WARNING
				"RV; UID %d cannot be traced\n", uid);
			return -1;
		}

		if (untrace_appuid(uid))
			printk("RV; stop tracing app with uid=%zu\n", uid);
		else
			printk("RV; app with uid=%zu was not traced\n", uid);

		return 0;
	}
	printk("RV; no info->attrs=%i\n", UID);
	return -1;
}

/*
 * register the operations for the family, i.e.,
 * define what function handles which command
 */
int droidtracer_register_genl_ops(void)
{
	int err;

	/* define mappings between the command identifier
	   and the actual handler */
	static struct genl_ops ops_trace_app = {
		/* command */
		.cmd = TRACE_APP,
		.flags = 0,
		.policy = policy,
		/* function that handles the received command */
		.doit = cb_trace_app,
		.dumpit = NULL,
	};
	static struct genl_ops ops_untrace_app = {
		.cmd = UNTRACE_APP,
		.flags = 0,
		.policy = policy,
		.doit = cb_untrace_app,
		.dumpit = NULL,
	};
	static struct genl_ops ops_blacklist_interface = {
		.cmd = ADD_BLACKLIST_INTERFACE,
		.flags = 0,
		.policy = policy,
		.doit = cb_blacklist_interface,
		.dumpit = NULL,
	};
	static struct genl_ops ops_remove_blacklist_interface = {
		.cmd = REMOVE_BLACKLIST_INTERFACE,
		.flags = 0,
		.policy = policy,
		.doit = cb_remove_blacklist_interface,
		.dumpit = NULL,
	};
	static struct genl_ops ops_whitelist_interface = {
		.cmd = ADD_WHITELIST_INTERFACE,
		.flags = 0,
		.policy = policy,
		.doit = cb_whitelist_interface,
		.dumpit = NULL,
	};
	static struct genl_ops ops_remove_whitelist_interface = {
		.cmd = REMOVE_WHITELIST_INTERFACE,
		.flags = 0,
		.policy = policy,
		.doit = cb_remove_whitelist_interface,
		.dumpit = NULL,
	};
	static struct genl_ops ops_set_droidtracer_uid = {
		.cmd = SET_DROIDTRACER_UID,
		.flags = 0,
		.policy = policy,
		.doit = cb_set_droidtracer_uid,
		.dumpit = NULL,
	};
	static struct genl_ops ops_set_lowest_uid_traced = {
		.cmd = SET_LOWEST_UID_TRACED,
		.flags = 0,
		.policy = policy,
		.doit = cb_set_lowest_uid_traced,
		.dumpit = NULL,
	};

	/* register operations for the family */
	err = genl_register_ops(&droidtracer_family, &ops_trace_app);
	if (err)
		goto err;

	err = genl_register_ops(&droidtracer_family, &ops_untrace_app);
	if (err)
		goto err;

	err = genl_register_ops(&droidtracer_family,
				&ops_blacklist_interface);
	if (err)
		goto err;

	err = genl_register_ops(&droidtracer_family,
				&ops_remove_blacklist_interface);
	if (err)
		goto err;

	err = genl_register_ops(&droidtracer_family,
				&ops_whitelist_interface);
	if (err)
		goto err;

	err = genl_register_ops(&droidtracer_family,
				&ops_remove_whitelist_interface);
	if (err)
		goto err;

	err = genl_register_ops(&droidtracer_family,
				&ops_set_droidtracer_uid);
	if (err)
		goto err;

	err = genl_register_ops(&droidtracer_family,
				&ops_set_lowest_uid_traced);
	if (err)
		goto err;

	return 0;

err:
	printk(KERN_ERR "RV; failed to register operation %i\n", err);
	/* unregister the family
	   note: all assigned operations are unregistered automatically */
	genl_unregister_family(&droidtracer_family);
	return -1;
}

static int cb_blacklist_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	char *iface;

	if (!info)
		goto out;

	/* for each attribute there is an index in info->attrs which
	 * points to a nlattr structure in this structure the data is
	 * given
	 */
	na = info->attrs[SERVICE];
	if (na) {
		// nla_len(na) is length of null terminated string
		iface = kmalloc(nla_len(na), GFP_KERNEL);
		nla_strlcpy(iface, na, nla_len(na));

		if (!iface) {
			printk(KERN_WARNING "RV; cannot allocate memory\n");
			goto out;
		}

		if (blacklist_iface(iface, nla_len(na), false))
			printk("RV; blacklisted interface=%s\n", iface);
		else
			printk("RV; interface=%s already blacklisted\n", iface);

		return 0;
	}
	printk("RV; no info->attrs=%i\n", SERVICE);

out:
	printk("RV; an error occured in cb_blacklist_interface\n");
	return -1;
}

static int cb_remove_blacklist_interface(struct sk_buff *skb,
					struct genl_info *info)
{
	// TODO
	return 0;
}


static int cb_whitelist_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	char *iface;

	if (!info)
		goto out;
	/*
	 * for each attribute there is an index in info->attrs which
	 * points to a nlattr structure in this structure the data is
	 * given
	 */
	na = info->attrs[SERVICE];
	if (na) {
		// nla_len(na) is length of null terminated string
		iface = kmalloc(nla_len(na), GFP_KERNEL);
		nla_strlcpy(iface, na, nla_len(na));

		if (!iface) {
			printk(KERN_WARNING "RV; cannot allocate memory\n");
			goto out;
		}

		if (blacklist_iface(iface, nla_len(na), true))
			printk("RV; whitelist interface= %s\n", iface);
		else
			printk("RV; %s is already whitelisted\n", iface);

		return 0;
	}
	printk("RV; no info->attrs=%i\n", SERVICE);

out:
	printk("RV; an error occured in cb_whitelist_interface\n");
	return -1;
}

static int cb_remove_whitelist_interface(struct sk_buff *skb,
					struct genl_info *info)
{
	// TODO
	return 0;
}

static int cb_set_droidtracer_uid(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;

	if (!info)
		printk("RV; an error occured in cb_set_droidtracer_uid\n");

	/* save PID of droidtracer service to communicate back */
	droidtracer_service_pid = info->snd_pid;

	na = info->attrs[UID];
	if (na) {
		uid_t uid = (uid_t) nla_get_u32(na);
		if (uid > 0) {
			droidtracer_uid = uid;
			printk("RV; droidtracer service UID set to %d\n", uid);
			return 0;
		}
	}

	printk("RV; no attr SERVICE info->attrs=%i\n", SERVICE);
	return -1;
}

static int cb_set_lowest_uid_traced(struct sk_buff *skb,
				struct genl_info *info)
{
	struct nlattr *na;

	if (!info)
		goto out;

	na = info->attrs[UID];
	if (na) {
		lowest_uid_traced = (uid_t) nla_get_u32(na);
		printk("RV; lowest UID traced set to %d\n", lowest_uid_traced);
		return 0;
	}
	printk("RV; no info->attrs=%i\n", UID);
out:
	printk("RV; an error occured in cb_set_lowest_uid_traced\n");
	return -1;
}

int trace_appuid(uid_t uid)
{
	struct rb_node **new = &(rbroot_appuids_traced.rb_node), *parent = NULL;
	struct rbnode_uid *data;
	struct rbnode_uid *this;

	/* Figure out where to put new node */
	while (*new) {
		//this = container_of(*new, struct rbnode_appuid, node);
		this = rb_entry(*new, struct rbnode_uid, node);
		parent = *new;

		if (uid < this->uid)
			new = &((*new)->rb_left);
		else if (uid > this->uid)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	data = kzalloc(sizeof(struct rbnode_uid), GFP_KERNEL);

	if (!data)
		printk(KERN_ERR
			"RV; cannot allocate memory for appuid: %d", uid);

	data->uid = uid;
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &rbroot_appuids_traced);

	appuid_counter++;
	return true;
}

static int untrace_appuid(uid_t uid) {
	struct rbnode_uid *data = get_appuid(uid);

	if (data) {
		rb_erase(&data->node, &rbroot_appuids_traced);
		kfree(data);

		appuid_counter--;
		return true;
	}
	return false;
}

static int insert_interface_len(uint8_t iface_len)
{
	struct rb_node **new = &(rbroot_filtered_interfaces.rb_node);
	struct rb_node *parent = NULL;
	struct rbnode_iface_len *data;
	struct rbnode_iface_len *this;

	/* Figure out where to put new node */
	while (*new) {
		this = rb_entry(*new, struct rbnode_iface_len, node);
		parent = *new;

		if (iface_len < this->len)
			new = &((*new)->rb_left);
		else if (iface_len > this->len)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	data = kzalloc(sizeof(struct rbnode_iface_len), GFP_KERNEL);

	if (!data)
		printk(KERN_ERR
			"RV; cannot allocate memory for iface_len node=%d",
			iface_len);

	data->len = iface_len;
	data->rbroot_ifaces = RB_ROOT;
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &rbroot_filtered_interfaces);

	return true;
}

static int blacklist_iface(char *iface, uint8_t iface_len, uint8_t whitelist)
{
	struct rb_node **new = NULL;
	struct rb_node *parent = NULL;
	struct rbnode_interface *data;
	struct rbnode_interface *this;

	insert_interface_len(iface_len);
	new = &(get_blacklisted_iface_len(iface_len)->rbroot_ifaces.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		//this = container_of(*new, struct rbnode_appuid, node);
		this = rb_entry(*new, struct rbnode_interface, node);
		parent = *new;

		if (strcmp(iface, this->name) < 0)
			new = &((*new)->rb_left);
		else if (strcmp(iface, this->name) > 0)
			new = &((*new)->rb_right);
		else
			return false;
  }

	/* Add new node and rebalance tree. */
	data = kzalloc(sizeof(struct rbnode_interface), GFP_KERNEL);

	if (!data)
		printk(KERN_ERR
			"RV; cannot allocate memory for iface node=%s", iface);

	data->name = iface;
	if (whitelist) {
		whitelist_empty = false;
		data->whitelist = true;
	} else {
		data->whitelist = false;
	}
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node,
			&get_blacklisted_iface_len(iface_len)->rbroot_ifaces);

	return true;
}
