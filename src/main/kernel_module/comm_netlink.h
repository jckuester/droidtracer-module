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

#ifndef COMM_NETLINK_H
#define COMM_NETLINK_H

#include <linux/rbtree.h>

// If defined prints debug messages with printk
//#define DEBUG_ON

// Turn off netlink for performance tests
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


/* attributes (variables): the index in this enum is used as a
 *             reference for the type, userspace application has to
 *             indicate the corresponding type the policy is used for
 *             security considerations
 */
enum {
	ATTR_UNSPEC,
	/* Linux UID of an app */
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

/* commands: enumeration of all commands (functions), 
 * used by userspace application to identify command to be ececuted
 */
enum {
	CMD_UNSPEC,
	ADD_APP,
	DELETE_APP,
	ADD_SERVICE_BLACKLIST,
	SET_DROIDTRACER_UID,
	ADD_SERVICE_WHITELIST,
	/* enable interception for all apps on the device */
	INTERCEPT_ALL_APPS,
	__CMD_MAX,
};
#define CMD_MAX (__CMD_MAX - 1)

#define VERSION_NR 1

struct rbnode_service_name {
	struct rb_node node_service_name;
	char *name;
	/* flag if service is part of white or black list */
	uint8_t is_in_whitelist;
};

/* function declarations */
int send_event(uint8_t, uint32_t, uint32_t, int, const void *, char *);
struct rbnode_appuid *search_appuid(uint32_t);
struct rbnode_services_len *search_service_len_blacklist(uint8_t);
struct rbnode_service_name *search_service_blacklist(char *, uint8_t);
int check_if_intercept(uint32_t);
int droidtracer_register_genl_ops(void);

/* global variables */
extern uint32_t droidtracer_uid;
extern uint8_t is_whitelist_empty;
extern uint8_t appuid_counter;
extern struct genl_family droidtracer_family;

#endif
