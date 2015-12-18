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
#include <../drivers/staging/android/binder.h>
#include "helper.h"

/*
 * removes every second 0 from sequence of uint8_t
 */
void binder_data_tostr(uint8_t *data_ptr, uint8_t data_len, char *result)
{
	int i;
	for (i = 0; i < data_len; i++) {
		*(result + i) = (char) *(data_ptr + 2*i);
	}	  
	*(result + data_len) = 0;
}

void print_debug(struct binder_transaction_data tr, uint8_t *data_ptr)
{
	int i;
	int j;
	int k;
	uint8_t *buffer_tmp;			
	uint8_t *buffer_tmp2;			

	const uint8_t *offsets_ptr = tr.data.ptr.offsets;

	// TODO intercept offsets, to get flat_binder_object, i.e.,
	// objects transferred through writeStrongBinder()
	if (tr.offsets_size > 0)
		printk("RV; offsets_size=%d, offset=", tr.offsets_size);
	for (k = 0; k<tr.offsets_size; k++) {
		printk("%d", *offsets_ptr);
		offsets_ptr++;
	}
	printk("\n");
	
	/* print tr.data.ptr.buffer (after service name) as string */
	buffer_tmp = (uint8_t *) data_ptr;
	//buffer_tmp = iface_ptr + 2*iface_len;
	printk(", buf_param_string=");
	for (i = 0; i<tr.data_size; i++) {
		printk("%c", *buffer_tmp);
		buffer_tmp++;
	}
	
	/* print tr.data.ptr.buffer (after service name) as uint8_t */
	printk(", buf_uint8_t=");
	//buffer_tmp2 = (uint8_t *) data_ptr;
	//buffer_tmp2 = iface_ptr + 2*iface_len;
	buffer_tmp2 = data_ptr;	    
	
	for (j = 0; j<tr.data_size; j++) {
		printk("%d ", *buffer_tmp2);
		buffer_tmp2++;
	}
	printk("\n");
}
