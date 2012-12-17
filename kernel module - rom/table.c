/**
 *\file  		table.c
 *@brief       	Internal route table
 *@ingroup		RT
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

int gw_reachable;

/**
 * route_table is the internal routing table, which holds all IPv4 addresses
 * from destinations which have a verified route. Verified routes are only
 * accepted by the routing logic using librom.
 * Note that we just save the destinations and not the route itself.
 */
static struct t_id route_table[ROUTE_TABLE_SIZE + 1];

/**
 * @brief Adds an IPv4 address to the internal routing table at the table's end
 *
 * @param dest destination address
 *
 * @return -1 or 0
 */
int add_route(struct t_id dest)
{
	int i = 0;

    if(dest.dst_addr == 0){
        return 0;
    }

	while (route_table[i].dst_addr != 0) {
		if (route_table[i].dst_addr == dest.dst_addr 
            || ((route_table[i].dst_mask & route_table[i].dst_addr) == (route_table[i].dst_mask & dest.dst_addr)))
			return 0;
		i++;
	}

	if (i < ROUTE_TABLE_SIZE) {
		route_table[i].dst_addr = dest.dst_addr;
		route_table[i].dst_mask = dest.dst_mask;
		return 0;
	}

	return -1;
}

/**
 * @brief delete_route deletes a destination from table by overwriting it with the
 * last table entry and set this last entry to zero afterwards
 *
 * @param dest destination address
 *
 * @return -1 or 0
 */
int delete_route(struct t_id dest)
{
	int i = 0, j;

	while ((route_table[i].dst_addr != dest.dst_addr) && i < ROUTE_TABLE_SIZE)
		i++;

	if (i == ROUTE_TABLE_SIZE)
		return -1;

	j = i;

	while (route_table[i].dst_addr != 0)
		i++;

	if (i <= ROUTE_TABLE_SIZE) {
		route_table[j].dst_addr = route_table[i - 1].dst_addr;
        route_table[j].dst_mask = route_table[i - 1].dst_mask;
		route_table[i - 1].dst_addr = 0;
		route_table[i - 1].dst_mask = 0xFFFFFFFF;
		return 0;
	}

	return -1;
}

/**
 * @brief ipv4_has_valid_route returns 1 if the given destination address is listed
 * in the table, otherwise 0.
 *
 * @param dst_addr destination address
 *
 * @return 1 or 0
 */
int ipv4_has_valid_route(__be32 dst_addr)
{
	int i = 0;

	while (i < ROUTE_TABLE_SIZE && ((route_table[i].dst_mask & route_table[i].dst_addr) != (route_table[i].dst_mask & dst_addr))){
        //__be32 temp1 = route_table[i].dst_mask & route_table[i].dst_addr;
        //__be32 temp2 = route_table[i].dst_mask & dst_addr;
        //printk(KERN_INFO "%s: teste ip&mask=%pI4 dest&mask=%pI4\n", DEBUG_ID, &temp1, &temp2);
        //printk(KERN_INFO "%s: teste ip=%pI4 mask=%pI4\n", DEBUG_ID, &route_table[i].dst_addr, &route_table[i].dst_mask);
		i++;
    }

	if (i == ROUTE_TABLE_SIZE || route_table[i].dst_addr == 0)
		return 0;

	return 1;
}

/**
 * @brief dump_route_table dumps the table to the kernel log
 */
void dump_route_table(void)
{
	int i;

	printk(KERN_INFO "%s: ROUTE TABLE DUMP:\n", DEBUG_ID);

	for (i = 0; route_table[i].dst_addr != 0; i++)
		printk(KERN_INFO "%s:   ip=%pI4 mask=%pI4\n", DEBUG_ID, &route_table[i].dst_addr, &route_table[i].dst_mask);
}
