/**
 *\file  		llf.c
 *@brief       	Link Layer Feedback
 *@details		Test detail
 *@ingroup		LLF
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

#include "rom.h"
#include <linux/module.h>

/**
 * @brief llf_handler description
 *
 * @param ip_daddr destination address
 */
void llf_handler(__be32 ip_daddr)
{
	if(enableLLF >= 1){
		struct t_id dest;
		dest.dst_addr = ip_daddr;
		dest.dst_mask = 0xFFFFFFFF;
		
		send_rom_rerr(ip_daddr);
		delete_route(dest);
	}
}

/**
 * @brief Initialize LLF
 */
void llf_init(void)
{
	if(enableLLF >= 1){
		if( register_llf_cb_function ){
			register_llf_cb_function( &llf_handler );
		}
	}
}

/**
 * @brief Unregister LLF
 */
void llf_exit(void)
{
	if(enableLLF >= 1){
		if( unregister_llf_cb_function ){
		    printk("unregister_llf_cb_function(  )...\n");
			unregister_llf_cb_function(  );
		}
		if( register_llf_cb_function ) {
		    printk("symbol_put( register_llf_cb )...\n");
		    symbol_put( register_llf_cb );
		}
		if( unregister_llf_cb_function ) {
		    printk("symbol_put( unregister_llf_cb )...\n");
		    symbol_put( unregister_llf_cb );
		}
	}
}

