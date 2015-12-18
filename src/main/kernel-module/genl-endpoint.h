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

#ifndef GENL_ENDPOINT_H
#define GENL_ENDPOINT_H

/* if defined prints debug messages with printk */
/* #define DEBUG_ON */
/* turn off netlink for performance tests */
#define NETLINK_ON

#ifdef DEBUG_ON
#  define D(x) x
#else
#  define D(x) 
#endif

#ifdef NETLINK_ON
#  define N(x) x
#else
#  define N(x)
#endif

/* 
 * attributes (variables): the index in this enum is used as a
 * reference for the type, userspace application has to indicate the
 * corresponding type the policy is used for security considerations
 */
enum {
	ATTR_UNSPEC,
	/* UID of an app */
	UID,  
	/* Unix time stamp when an event is intercepted in the kernel */
	TIME,
	/* encoded Android API method name in binder_tranaction_data */
	CODE,
	/* byte array of intercepted Parcel object */
	PARCEL,
	/* name of the service interface */
	SERVICE,
	__ATTR_MAX,
};
#define ATTR_MAX (__ATTR_MAX - 1)

/* 
 * commands: enumeration of all commands (functions), 
 * used by userspace application to identify command to be ececuted
 */
enum {
	CMD_UNSPEC,
	TRACE_APP,
	UNTRACE_APP,
	BLACKLIST_INTERFACE,
	WHITELIST_INTERFACE,
	SET_DROIDTRACER_UID,
	SET_LOWEST_UID_TRACED,
	__CMD_MAX,
};
#define CMD_MAX (__CMD_MAX - 1)

#define VERSION_NR 1

/* function declarations */
int send_event(uint8_t code, uid_t appuid, uint32_t time, int data_size,
	const void *data, char *syscall);
struct rbnode_uid *get_appuid(uid_t uid);
struct rbnode_iface_len *get_blacklisted_iface_len(uint8_t);
struct rbnode_interface *get_blacklisted_iface(char *, uint8_t);
int intercept(uint32_t uid);
int droidtracer_register_genl_ops(void);
int trace_appuid(uid_t uid);

/* global variables */
extern uid_t droidtracer_uid;
extern uint8_t whitelist_empty;
extern uint8_t appuid_counter;
extern struct genl_family droidtracer_family;

struct rbnode_interface {
	struct rb_node node;
	char *name;
	/* flag if service is part of white or black list */
	uint8_t whitelist;
};

#endif
