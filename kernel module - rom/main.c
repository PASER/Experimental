/**
 *\file  		main.c
 *@brief       	main.c is responsible for loading and unloading the route-o-matic module
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

/**
 *\mainpage 	route-o-matic - A reactive routing framework for Linux
 *\section     	Overview Overview of the implementation of the route-o-matic kernel module
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

/**
 *  @defgroup LLF Link Layer Feedback
 *  @defgroup NS Netlink Server
 *  @defgroup PM Packet Monitor
 *  @defgroup Queue Queue
 *  @defgroup RT Route Table
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/inet.h>
#include "rom.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("route-o-matic - A reactive routing framework for Linux");

int isGateway = 0;
module_param(isGateway, int, 0);
MODULE_PARM_DESC(isGateway, "Is the node a gateway.");

/*
 * IP address and mask of all own subnetworks
 * Format: mySubnetworks[] = {"IP-1", "Mask-1"
 *                            "IP-2", "Mask-2" ...}
 */
char* mySubnetworks[10];
int mySubnetworksSize = 0;
module_param_array(mySubnetworks, charp, &mySubnetworksSize, 0000);
MODULE_PARM_DESC(mySubnetworks, "IP address and Masks of own subnetworks.");

int enableLLF = 0;
module_param(enableLLF, int, 0);
MODULE_PARM_DESC(enableLLF, "Enable LLF support.");

int LLFPerSecond = 0;
module_param(LLFPerSecond, int, 0);
MODULE_PARM_DESC(LLFPerSecond, "Required number of LLFs in a second to trigger the LLF signal.");

int (*unregister_llf_cb_function)(void);
int (*register_llf_cb_function)(void (*cbfn) (__be32 ip_daddr));

/**
 * @brief Initialize the route-o-matic kernel module
 */
static int __init rom_init(void)
{
	printk(KERN_INFO "%s: loading kernel module...\n", DEBUG_ID);

	gw_reachable = isGateway;

	if (queue_init() != 0) {
		printk(KERN_ALERT "%s: queue creation failed\n", DEBUG_ID);
		return -1;
	}

	if (netlink_init() != 0) {
		printk(KERN_ALERT "%s: netlink error\n", DEBUG_ID);
		destroy_queue();
		return -1;
	}

	nfhook_init();

	if(enableLLF >= 1){
		printk("Looking for register_llf_cb...\n");
		register_llf_cb_function = symbol_get( register_llf_cb );
		if( register_llf_cb_function ){
			//register_llf_cb_function( &llf_handler );
		}
		else{
			printk("can't find address of symbol \"register_llf_cb(void (*cbfn) (__be32 ip_daddr))\"\n");
			nfhook_exit();
			netlink_exit();
			destroy_queue();
			return -1;
		}
		printk("Looking for unregister_llf_cb(void)...\n");
		unregister_llf_cb_function = symbol_get( unregister_llf_cb );
		if( unregister_llf_cb_function ){
			//unregister_llf_cb_function(  );
		}
		else{
			printk("can't find address of symbol \"unregister_llf_cb(void)\"\n");
			nfhook_exit();
			netlink_exit();
			destroy_queue();
			return -1;
		}
		llf_init();
	}

	return 0;
}

/**
 * @brief Unload kernel module
 */
static void __exit rom_exit(void)
{
	printk(KERN_INFO "%s: unloading kernel module...\n", DEBUG_ID);

	if(enableLLF >= 1){
		llf_exit();
	}

	nfhook_exit();
	netlink_exit();
	destroy_queue();
}

module_init(rom_init);
module_exit(rom_exit);
