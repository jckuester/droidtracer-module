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

#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

// TODO: import struct's below directly from binder.h/binder.c

enum {
        BINDER_STAT_PROC,
        BINDER_STAT_THREAD,
        BINDER_STAT_NODE,
        BINDER_STAT_REF,
        BINDER_STAT_DEATH,
        BINDER_STAT_TRANSACTION,
        BINDER_STAT_TRANSACTION_COMPLETE,
        BINDER_STAT_COUNT
};

struct binder_stats {
        int br[_IOC_NR(BR_FAILED_REPLY) + 1];
        int bc[_IOC_NR(BC_DEAD_BINDER_DONE) + 1];
        int obj_created[BINDER_STAT_COUNT];
        int obj_deleted[BINDER_STAT_COUNT];
};

static struct binder_stats binder_stats;

struct binder_work {
	struct list_head entry;
	enum {
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	} type;
};

struct binder_proc {
        struct hlist_node proc_node;
        struct rb_root threads;
        struct rb_root nodes;
        struct rb_root refs_by_desc;
        struct rb_root refs_by_node;
        int pid;
        struct vm_area_struct *vma;
        struct task_struct *tsk;
        struct files_struct *files;
        struct hlist_node deferred_work_node;
        int deferred_work;
        void *buffer;
        ptrdiff_t user_buffer_offset;

        struct list_head buffers;
        struct rb_root free_buffers;
        struct rb_root allocated_buffers;
        size_t free_async_space;

        struct page **pages;
        size_t buffer_size;
        uint32_t buffer_free;
        struct list_head todo;
        wait_queue_head_t wait;
        struct binder_stats stats;
        struct list_head delivered_death;
	int max_threads;
        int requested_threads;
        int requested_threads_started;
        int ready_threads;
        long default_priority;
};

struct binder_thread {
	struct binder_proc *proc;
	struct rb_node rb_node;
	int pid;
	int looper;
	struct binder_transaction *transaction_stack;
	struct list_head todo;
	uint32_t return_error; /* Write failed, return error code in read buf */
	uint32_t return_error2; /* Write failed, return error code in read */
	/* buffer. Used when sending a reply to a dead process that */
	/* we are also waiting on */
	wait_queue_head_t wait;
	struct binder_stats stats;
};

struct binder_transaction {
	int debug_id;
	struct binder_work work;
	struct binder_thread *from;
	struct binder_transaction *from_parent;
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	struct binder_transaction *to_parent;
	unsigned need_reply : 1;
	/*unsigned is_dead : 1;*/ /* not used at the moment */
	
	struct binder_buffer *buffer;
	unsigned int    code;
	unsigned int    flags;
	long    priority;
	long    saved_priority;
	uid_t   sender_euid;
};

struct binder_buffer {
	struct list_head entry; /* free and allocated entries by addesss */
	struct rb_node rb_node; /* free entry by size or allocated entry */
	/* by address */
	unsigned free : 1;
	unsigned allow_user_free : 1;
	unsigned async_transaction : 1;
	unsigned debug_id : 29;
	
	struct binder_transaction *transaction;
	
	struct binder_node *target_node;
	size_t data_size;
	size_t offsets_size;
	uint8_t data[0];
};


struct binder_ref {
	/* Lookups needed: */
	/*   node + proc => ref (transaction) */
	/*   desc + proc => ref (transaction, inc/dec ref) */
	/*   node => refs + procs (proc exit) */
	int debug_id;
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	struct hlist_node node_entry;
	struct binder_proc *proc;
	struct binder_node *node;
	uint32_t desc;
	int strong;
	int weak;
  struct binder_ref_death *death;
};

struct binder_node {
	int debug_id;
	struct binder_work work;
	union {
		struct rb_node rb_node;
		struct hlist_node dead_node;
  };
	struct binder_proc *proc;
	struct hlist_head refs;
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	void __user *ptr;
	void __user *cookie;
	unsigned has_strong_ref : 1;
	unsigned pending_strong_ref : 1;
	unsigned has_weak_ref : 1;
	unsigned pending_weak_ref : 1;
	unsigned has_async_transaction : 1;
	unsigned accept_fds : 1;
	int min_priority : 8;
	struct list_head async_todo;
};

#endif
