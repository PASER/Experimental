/**
 *\file  		queue.c
 *@brief       	Queue buffer implementation
 *@ingroup		Queue
 *\authors     	Carsten.Vogel | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http://www.kn.e-technik.tu-dortmund.de/
 *
 *
 *              This program is free software; you can redistribute it
 *              and/or modify it under the terms of the GNU General Public
 *              License as published by the Free Software Foundation; either
 *              version 2 of the License, or (at your option) any later
 *              version.
 *              For further information see file COPYING
 *              in the top level directory
 ********************************************************************************
 * This work is part of the secure wireless mesh networks framework, which is currently under development by CNI
 ********************************************************************************\n\n
 *
 *
 * ## The route-o-matic queue format:
 *
 * q_list: A double-linked list which manages the different packet queues for
 *         every destination. The members of this list are q_head structures.
 *
 * q_head: There is one q_head for every destination address (non-private
 *         addresses share one queue for 0.0.0.0). It contains the address and
 *         the actual queue q_buf.
 *
 * q_buf:  This is the FIFO buffer which holds pointers to both the queued
 *         packets and their next-processing function (okfn).
 */

#include <linux/netfilter_ipv4.h>
#include <linux/kfifo.h>
#include <net/ip.h>
#include "rom.h"



/**
 * \internal
 * @brief It contains the address and the actual queue q_buf.
 *
 * There is one q_head for every destination address (non-private addresses share one queue for 0.0.0.0).
 */
struct q_head {
	__be32			dst_addr;  	///< IPv4 destination address
	struct kfifo		q_buf;	///< FIFO buffer (the queue)
	struct list_head	list;   ///< used for list linking
};

/// defines the queue list as struct list_head
static LIST_HEAD(q_list);

/**
 * @brief For a given destination dst_addr get_queue_for_dst will return a pointer to
 * its queue head if it exists, otherwise NULL
 *
 * @param dst_addr destination address
 *
 * @return pointer to queue or 0
 */
static struct q_head *get_queue_for_dst(__be32 dst_addr)
{
	struct q_head *qh;

	/*
	 * using reverse lookup order here will find external queue in O(1)
	 * runtime, because it is always the last entry in the queue list
	 */
	list_for_each_entry_reverse(qh, &q_list, list) {
		if (qh->dst_addr == dst_addr)
			return qh;
	}

	return NULL;
}

/**
 * @brief create_queue_for_dst will create a new queue by allocating memory for both
 * the q_head structure and the q_buf FIFO buffer and adding the created struct
 * q_head to q_list
 *
 * @param dst_addr destination address
 *
 * @return struct q_head
 */
static struct q_head *create_queue_for_dst(__be32 dst_addr)
{
	struct q_head *new_qh;

	if (DEBUG_ROM)
		printk(KERN_INFO "%s: create_queue_for_dst(%pI4)\n", DEBUG_ID,
								&dst_addr);

	new_qh = kmalloc(sizeof(*new_qh), GFP_ATOMIC);
	//new_qh = kmalloc(sizeof(*new_qh), GFP_KERNEL);
	new_qh->dst_addr = dst_addr;

	if (kfifo_alloc(&new_qh->q_buf, QUEUE_SIZE, GFP_ATOMIC) != 0) {
	//if (kfifo_alloc(&new_qh->q_buf, QUEUE_SIZE, GFP_KERNEL) != 0) {
		printk(KERN_ALERT "%s: kfifo_alloc() error\n", DEBUG_ID);
		return NULL;
	}

	INIT_LIST_HEAD(&new_qh->list);

	list_add(&new_qh->list, &q_list);

	return new_qh;
}

/**
 * @brief release_queue_for_dst will reinject all queued packets for a specific
 * destination and delete the corresponding queue afterwards, if it is not the
 * external queue
 *
 * @param dest destination address
 *
 * @return 0 or -EINVAL
 */
int release_queue_for_dst(struct t_id dest)
{
	struct q_head *qh;
	struct sk_buff *skb;
	int (*okfn) (struct sk_buff *);

loop_begin:
	list_for_each_entry_reverse(qh, &q_list, list) {
		if ((qh->dst_addr & dest.dst_mask) == (dest.dst_addr & dest.dst_mask)){
	        while (!kfifo_is_empty(&qh->q_buf)) {
		        int ret;

		        ret = kfifo_out(&qh->q_buf, &skb, sizeof(skb));
		        if (ret != sizeof(skb))
			        return -EINVAL;

		        ret = kfifo_out(&qh->q_buf, &okfn, sizeof(okfn));
		        if (ret != sizeof(okfn))
			        return -EINVAL;

		        okfn(skb);
	        }

	        if (dest.dst_addr != 0) {
		        kfifo_free(&qh->q_buf);
		        list_del(&qh->list);
		        kfree(qh);
                goto loop_begin;
	        }
        }
	}

	return 0;
}

/**
 * @brief enqueue_packet checks if a queue already exists for a given destination
 * dst_addr. If not a queue is created.
 * Afterwards the packet is added to the queue by adding both pointers for the
 * packet *skb and the next-processing funcition *okfn to the queue FIFO buffer
 *
 * @param skb socket-buffer
 * @param okfn okfn
 * @param dst_addr destination address
 *
 * @return ...
 */
static void enqueue_packet(struct sk_buff *skb, int (*okfn) (struct sk_buff *),
								__be32 dst_addr)
{
	struct q_head *qh;
	struct sk_buff *rom_skb;
	unsigned int p_num;	// number of already queued packets
	unsigned int p_max;	// maximum number of packets per queue buffer

	qh = get_queue_for_dst(dst_addr);

	if (qh == NULL) {
		/* No queue for that destination yet, so we create a new one */
		qh = create_queue_for_dst(dst_addr);

		if (qh == NULL) {
			printk(KERN_WARNING "%s: Cannot create queue - discarding packet!\n",
								DEBUG_ID);
			kfree_skb(skb);
			return;
		}
	}

	p_max = kfifo_size(&qh->q_buf) / (sizeof(skb) + sizeof(okfn));
	p_num = kfifo_len(&qh->q_buf) / (sizeof(skb) + sizeof(okfn));

	if (DEBUG_ROM_VERBOSE)
		printk(KERN_INFO "%s: Queued packets for %pI4 (max: %d): %d\n",
								DEBUG_ID,
								&qh->dst_addr,
								p_max,
								p_num);

	/* check if there is enough space left in queue buffer */
	if ((p_max - p_num) >= 1) {
		rom_skb = skb_copy(skb, GFP_ATOMIC);
		//rom_skb = skb_copy(skb, GFP_KERNEL);

		if (rom_skb) {
			kfifo_in(&qh->q_buf, &rom_skb, sizeof(rom_skb));
			kfifo_in(&qh->q_buf, &okfn, sizeof(okfn));
		} else {
			printk(KERN_WARNING "%s: Could not copy skb!\n",
								DEBUG_ID);
		}
	} else {
#ifdef REPLACE_QUEUE_ENTRY
		// delete first packet in FIFO and put new packet to FIFO
		int ret = kfifo_out(&qh->q_buf, &rom_skb, sizeof(rom_skb));
		if (ret == sizeof(skb)){
			// delete old packet
			kfree_skb(rom_skb);

			// put new packet to FIFO
			rom_skb = skb_copy(skb, GFP_ATOMIC);
			if (rom_skb) {
				kfifo_in(&qh->q_buf, &rom_skb, sizeof(rom_skb));
				kfifo_in(&qh->q_buf, &okfn, sizeof(okfn));
			} else {
				printk(KERN_WARNING "%s: Could not copy skb!(replace)\n", DEBUG_ID);
			}
		}
		else
#endif
		if (DEBUG_ROM_VERBOSE)
			printk(KERN_WARNING "%s: queue full: discarding packet\n",
								DEBUG_ID);
	}

	kfree_skb(skb);
}

/**
 * @brief check_and_send_rreq checks if there are already buffered packets for the same
 * destination. If not it initiates a RREQ to user space
 *
 * @param dst_addr destination address
 *
 * @return void
 */
static void check_and_send_rreq(__be32 dst_addr)
{
	struct q_head *qh;
	qh = get_queue_for_dst(dst_addr);
	if (qh == NULL) {
		if (DEBUG_ROM)
			printk(KERN_INFO "%s: Send RREQ for %pI4\n", DEBUG_ID,
								&dst_addr);
		if (send_rom_rreq(dst_addr) != 0)
				printk(KERN_WARNING "%s: No RREQ sent for %pI4\n",
							DEBUG_ID, &dst_addr);
		return;
	}


	if (dst_addr == 0) {
		if (kfifo_len(&qh->q_buf) == 0) {
			if (DEBUG_ROM)
				printk(KERN_INFO "%s: Send RREQ for %pI4\n",
							DEBUG_ID, &dst_addr);
			if (send_rom_rreq(dst_addr) != 0)
				if (DEBUG_ROM)
					printk(KERN_WARNING "%s: No RREQ sent for %pI4\n",
							DEBUG_ID, &dst_addr);
			return;
		}
	}

    if (DEBUG_ROM)
		printk(KERN_INFO "%s: Send RREQ for %pI4\n",DEBUG_ID, &dst_addr);
    if (send_rom_rreq(dst_addr) != 0)
        if (DEBUG_ROM)
		    printk(KERN_WARNING "%s: No RREQ sent for %pI4\n", DEBUG_ID, &dst_addr);

}

/**
 * @brief queue_packet_handler is invoked by the route-o-matic netfilter hook for each
 * packet which needs to be queued. It will send out a RREQ message if necessary
 * and enqueue the packet.
 *
 * @param *skb socket buffer
 * @param okfn okfn
 * @param ext_dest ext_dest
 *
 * @return void
 */
void queue_packet_handler(struct sk_buff *skb,
				int (*okfn) (struct sk_buff *),
				int ext_dest)
{
	__be32 dst_addr = 0;

	if (!ext_dest)
		dst_addr = ip_hdr(skb)->daddr;

	check_and_send_rreq(dst_addr);
	enqueue_packet(skb, okfn, dst_addr);
}

/**
 * @brief dump_queue_list dumps the whole buffer to kernel log
 */
void dump_queue_list(void)
{
	struct q_head *qh;
	int i, max;

	printk(KERN_INFO "%s: QUEUE DUMP:\n", DEBUG_ID);
	list_for_each_entry_reverse(qh, &q_list, list) {
		i = kfifo_len(&qh->q_buf);
		max = kfifo_size(&qh->q_buf);
		/* Below: 8 = sizeof(*skb) + sizeof(*okfn) = 2 * 4 Bytes */
		printk(KERN_INFO "%s:    Queued packets for %pI4 (max: %d): %d\n",
								DEBUG_ID,
								&qh->dst_addr,
								max/8,
								i/8);
	}
}

/**
 * @brief queue_init will initialize the queue list with one shared queue for packets
 * for all non-private destinations (identified by 0.0.0.0)
 */
int queue_init(void)
{
	if (create_queue_for_dst(0))
		return 0;
	else
		return -1;
}

/**
 * @brief destroy_queue will free the allocated memory for ALL q_head structures and
 * the queue FIFO buffers including the shared non-private queue. All buffered
 * packets will be discarded without reinjecting. If you want to reinject them
 * before you have to do this manually using a QREL message.
 * Call this function for a clean termination of route-o-matic.
 */
void destroy_queue(void)
{
	struct q_head *qh, *next;
	struct sk_buff *skb;
	int (*okfn) (struct sk_buff *);

	/* loop through all queues in list for each destination */
	list_for_each_entry_safe(qh, next, &q_list, list) {
		if (DEBUG_ROM)
			printk(KERN_INFO "%s: delete queue for %pI4\n",
								DEBUG_ID,
								&qh->dst_addr);

		/* free all packets */
		while (!kfifo_is_empty(&qh->q_buf)) {
			int ret;

			ret = kfifo_out(&qh->q_buf, &skb, sizeof(skb));
			if (ret != sizeof(skb))
				break;

			ret = kfifo_out(&qh->q_buf, &okfn, sizeof(okfn));
			if (ret != sizeof(okfn))
				break;

			kfree_skb(skb);
		}

		kfifo_free(&(qh->q_buf));
		list_del(&qh->list);
		kfree(qh);
	}
}
