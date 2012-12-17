/**
 *\file  		nfhook.c
 *@brief       	Packet Monitor implementation
 *@ingroup		PM
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
 ********************************************************************************/

#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <net/route.h>
#include "rom.h"

static struct nf_hook_ops nfho_remote;
static struct nf_hook_ops nfho_local;

/**
 * @brief The whitelist contains all IPv4 addresses of this host.
 *
 * It is used to filter out all packets which are destined for this host as early as possible
 */
static struct t_id whitelist[WHITELIST_SIZE + 1];

/**
 * @brief Build the whitelist
 *
 * We loop through all existing network devices to get their IPv4 and broadcast addresses
 */
static void init_whitelist(void)
{
	struct in_device *in_dev;
    struct in_device *in_dev_temp;
	struct net_device *dev;
	int j, dup;
	int i = 0;
    int k = 0;

	read_lock(&dev_base_lock);

	dev = first_net_device(&init_net);

	while (dev) {
		//if (DEBUG_ROM)
			printk(KERN_INFO "%s: found device %s\n", DEBUG_ID,
								dev->name);

		in_dev = in_dev_get(dev);
        in_dev_temp = in_dev;
		/*
		 * Loop through all IP addresses/broadcast address pairs
		 * which are bound to the current device in_dev
		 * These include the primary IPv4 address, IPv4 aliases and all
		 * their corresponding broadcast addresses
		 */
		for_ifa(in_dev) {
			if (i >= WHITELIST_SIZE)
				break;

			/*
			 * Loopback addresses are skipped, because they will be
			 * filtered out before whitelist
			 */
			if (ipv4_is_loopback(ifa->ifa_address))
				break;

			/* Add IPv4 address to whitelist */
			whitelist[i].dst_addr = ifa->ifa_address;
            whitelist[i].dst_mask = 0xFFFFFFFF;
			i++;

			if (i >= WHITELIST_SIZE)
				break;

			/*
			 * Add IPv4 broadcast address to whitelist and eliminate
			 * duplicate entries
			 */
			dup = 0;

			for (j = 0; j < i; j++) {
				if (whitelist[j].dst_addr == ifa->ifa_broadcast) {
					dup = 1;
					break;
				}
			}

			if (!dup) {
				whitelist[i].dst_addr = ifa->ifa_broadcast;
                whitelist[i].dst_mask = 0xFFFFFFFF;
				i++;
			}
		} endfor_ifa(in_dev);

		if (i >= WHITELIST_SIZE) {
			printk(KERN_WARNING "%s: Whitelist full!\n", DEBUG_ID);
			break;
		}

        in_dev_put(in_dev_temp);
		dev = next_net_device(dev);
	}

	read_unlock(&dev_base_lock);

    printk(KERN_INFO "mySubnetworksSize = %d\n", mySubnetworksSize);
    if((mySubnetworksSize/2)*2 == mySubnetworksSize){
        /* load own subnetworks to witelist*/
        for(k=0; k<mySubnetworksSize && (k/2)+i<WHITELIST_SIZE; k++,i++){
            whitelist[i].dst_addr = in_aton(mySubnetworks[k]);
            k++;
            whitelist[i].dst_mask = in_aton(mySubnetworks[k]);
        }
    }
    else{
        printk(KERN_INFO "%s: Cann't add own subnetworks to witelist.\n", DEBUG_ID);
    }

//	if (DEBUG_ROM) {
    if (true) {
		printk(KERN_INFO "%s: WHITELIST DUMP:\n", DEBUG_ID);
		for (j = 0; j < i; j++)
			printk(KERN_INFO "%s:    IP: %pI4, MASK: %pI4\n", DEBUG_ID,
							&whitelist[j].dst_addr, &whitelist[j].dst_mask );
	}
	/* null-terminate whitelist */
	whitelist[i].dst_addr = 0;
    whitelist[i].dst_mask = 0;
}

/**
 * @brief unsigned int hook_func description
 *
 * @param hooknum hooknum
 * @param skb skb
 * @param in in
 * @param out out
 * @param sk_buff sk_buff
 *
 * @return NF_ACCEPT
 */
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb,
					const struct net_device *in,
					const struct net_device *out,
					int (*okfn) (struct sk_buff *))
{
	const struct iphdr *iph;
	struct t_id *wl_addr = whitelist;

    struct sk_buff *sock_buff;
    sock_buff = skb;
    if(!sock_buff){ 
        printk("sock buff null\n"); 
        return NF_ACCEPT; 
    }
	iph = (const struct iphdr *) skb_network_header(skb);
	
	if(iph->version != 4){
		return NF_ACCEPT;
	}
	
	/* accept all loopback traffic */
	if (ipv4_is_loopback(iph->daddr))
		return NF_ACCEPT;

	/* accept packets for whitelisted destinations */
	do {
		if ((iph->daddr & wl_addr->dst_mask) == (wl_addr->dst_addr & wl_addr->dst_mask)) {
			if (DEBUG_ROM_VERBOSE){
				printk(KERN_INFO "%s: %d Accept (whitelist): %pI4 -> %pI4\n",
								DEBUG_ID,
								hooknum,
								&iph->saddr,
								&iph->daddr);
                printk(KERN_INFO "%s: %d witelistentry IP: %pI4, Mask: %pI4\n",
								DEBUG_ID,
								hooknum,
								&(wl_addr->dst_addr),
								&(wl_addr->dst_mask));
                }
			return NF_ACCEPT;
		}
	} while ((wl_addr++) && wl_addr->dst_addr);

	/* Filter all packets for external (non-private) destinations  */
	if (/* !ipv4_is_private_10(iph->daddr) && !ipv4_is_private_172(iph->daddr)
					  && */!ipv4_is_private_192(iph->daddr) && !ipv4_is_lbcast(iph->daddr)) {

		if (gw_reachable) {
			if (DEBUG_ROM_VERBOSE)
				printk(KERN_INFO "%s: %d Accept (GW reachable): %pI4 -> %pI4\n",
								DEBUG_ID,
								hooknum,
								&iph->saddr,
								&iph->daddr);
			return NF_ACCEPT;
		} else {
			if (DEBUG_ROM_VERBOSE)
				printk(KERN_INFO "%s: %d Queue (GW NOT reachable): %pI4 -> %pI4\n",
								DEBUG_ID,
								hooknum,
								&iph->saddr,
								&iph->daddr);
			queue_packet_handler(skb, okfn, 1);
			return NF_STOLEN;
		}
	}

	/* XXX: Filter out X.X.X.255 broadcast packets
	 *
	 * We accept all packets with destination address ending in .255, since
	 * in our test environment we can be sure these are broadcast packets.
	 *
	 * However, it is not a good solution which can cause both false
	 * positves and negatives in a different environment! So be warned!
	 *
	 * Short explanation why this is a hack (quoted from C. Benvenuti -
	 * Understanding Linux Network Internals):
	 * "subnet broadcasts cannot be recognized without involving the routing
	 * table with fib_lookup. For example, the address 10.0.1.127 might be a
	 * subnet broadcast in 10.0.1.0/25, but not in 10.0.1.0/24."
	 */
	if ((ntohl(iph->daddr) & 0x000000FF) == 0x000000FF) {
    	if (DEBUG_ROM)
			printk(KERN_INFO "%s: %d Accept (broadcast): %pI4 -> %pI4\n",
								DEBUG_ID,
								hooknum,
								&iph->saddr,
								&iph->daddr);
		return NF_ACCEPT;
	}
	/* End of broadcast workaround */

    //dump_route_table();
	if (ipv4_has_valid_route(iph->daddr)) {
		if (DEBUG_ROM_VERBOSE)
			printk(KERN_INFO "%s: %d Accept (table hit): %pI4 -> %pI4\n",
								DEBUG_ID,
								hooknum,
								&iph->saddr,
								&iph->daddr);
        send_rom_rlife(iph->daddr);
		return NF_ACCEPT;
	} else {
		if (DEBUG_ROM_VERBOSE)
			printk(KERN_INFO "%s: %d Queue (table miss): %pI4 -> %pI4\n",
								DEBUG_ID,
								hooknum,
								&iph->saddr,
								&iph->daddr);
		queue_packet_handler(skb, okfn, 0);
		return NF_STOLEN;
	}

	/* No packet should ever reach here! */
	printk(KERN_ALERT "%s: BUG! Unchecked package in nfhook!\n", DEBUG_ID);
	return NF_ACCEPT;
}

/**
 * @brief nfhook_init description
 */
int nfhook_init(void)
{
	init_whitelist();

	nfho_remote.hook = hook_func;
	nfho_remote.hooknum = NF_INET_PRE_ROUTING;
	nfho_remote.pf = PF_INET;
	nfho_remote.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_remote);

	nfho_local.hook = hook_func;
	nfho_local.hooknum = NF_INET_LOCAL_OUT;
	nfho_local.pf = PF_INET;
	nfho_local.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_local);

	return 0;
}

/**
 * @brief nfhook_exit description
 */
void nfhook_exit(void)
{
	nf_unregister_hook(&nfho_remote);
	nf_unregister_hook(&nfho_local);
}
