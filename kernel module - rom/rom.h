/**
 *\file  rom.h
 *@brief       Properties and definitions of the route-o-matic kernel module
 *\authors     Carsten.Vogel | Mohamad.Sbeiti \@paser.info
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
 ********************************************************************************/


#ifndef __ROM_H
#define __ROM_H
#include <linux/skbuff.h>

#define REPLACE_QUEUE_ENTRY
#define limit_RLIFE

/**
 * Debugging options:
 *
 * Set DEBUG_ROM=1 to print out some runtime info to kernel log
 *
 * Set DEBUG_ROM_VERBOSE=1 to produce a LOT of output for every packet that is
 * processed in the netfilter hook.
 * Caution: this will let the kernel logfile grow HUGE quickly if you got lots
 * of traffic!
 *
 * All printk() statments will begin with DEBUG_ID
 */
#define DEBUG_ROM		0
#define DEBUG_ROM_VERBOSE	0
#define DEBUG_ID		"rom"

/// maximum number of whitelist entries
#define WHITELIST_SIZE	32

/// maximum number of route entries
#define ROUTE_TABLE_SIZE 32

/**
 * QUEUE_SIZE defines the buffer size in bytes which will be allocated for each
 * queue. Each queued packet needs two pointers stored in this buffer which will
 * be 8 bytes on systems with 32-bit pointers. It is good practice to take a
 * multiple of a PAGE_SIZE here. However this makes its size platform-dependent.
 * For example a common PAGE_SIZE size is 4KB which means you can queue 512
 * packets.
 * The default here is one PAGE_SIZE
 */
#define QUEUE_SIZE		(2 * PAGE_SIZE)

/**
 * Support for Link Layer Feedback (experimental)
 *
 * Since link layer feedback currently only works with modified WLAN drivers,
 * support is disabled by default. To activate link layer feedback support you
 * have to add the following line:
 *
 * #define ENABLE_LLF_SUPPORT
 */
//#define ENABLE_LLF_SUPPORT
//#define LLF_IN_SECONDS 5
extern int enableLLF;
extern int LLFPerSecond;

/**
 * \internal
 * @brief t_id description
 */
struct t_id{
    __be32			dst_addr;  ///< IPv4 destination address
    __be32			dst_mask;  ///< IPv4 destination mask
};

extern int isGateway;
extern char* mySubnetworks[];
extern int mySubnetworksSize;

extern int gw_reachable;

extern int release_queue_for_dst(struct t_id dst_addr);
extern void queue_packet_handler(struct sk_buff *skb,
					int (*okfn) (struct sk_buff *),
					int ext_dest);
extern int queue_init(void);
extern void destroy_queue(void);
extern void dump_queue_list(void);

extern int netlink_init(void);
extern void netlink_exit(void);
extern int send_rom_rreq(__be32 dst_addr);
extern int send_rom_rlife(__be32 dst_addr);
extern int send_rom_rerr(__be32 dst_addr);

extern int nfhook_init(void);
extern void nfhook_exit(void);

extern int add_route(struct t_id dst_addr);
extern int delete_route(struct t_id dst_addr);
extern int ipv4_has_valid_route(__be32 dst_addr);
extern void dump_route_table(void);

extern void llf_init(void);
extern void llf_exit(void);

extern int register_llf_cb(void (*cbfn) (__be32 ip_daddr));
extern int unregister_llf_cb(void);

extern int (*unregister_llf_cb_function)(void);
extern int (*register_llf_cb_function)(void (*cbfn) (__be32 ip_daddr));

#endif	/* __ROM_H */
