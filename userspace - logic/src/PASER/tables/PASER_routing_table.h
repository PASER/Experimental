/**
 *\class  		PASER_routing_table
 *@brief       	Class provides a map of node's routes.
 *@ingroup 		Tables
 *\authors    	Eugen.Paul | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http:///www.kn.e-technik.tu-dortmund.de/
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

class PASER_routing_table;

#ifndef PASER_ROUTING_TABLE_H_
#define PASER_ROUTING_TABLE_H_

#include <map>
#include <list>

#include "openssl/x509.h"

#include "PASER_routing_entry.h"
#include "PASER_neighbor_table.h"
#include "PASER_neighbor_entry.h"
#include "../timer_management/PASER_timer_packet.h"
#include "../timer_management/PASER_timer_queue.h"
#include "../config/PASER_global.h"

#include <sstream>
#include <stdlib.h>
#include <string.h>

/**
 * Implementation of the routing table.
 * Each valid route will be automatically added to the kernel routing table.
 */
class PASER_routing_table {
private:
    /**
     * Map of node's routes.
     * Key   - IP address of the node.
     * Value - Pointer to the node's route entry.
     */
    std::map<Uint128, PASER_routing_entry*> route_table;

private:
    PASER_timer_queue *timer_queue;
    PASER_neighbor_table *neighbor_table;
    PASER_global *pGlobal;

public:
    PASER_routing_table(PASER_global *paser_global);
    ~PASER_routing_table();

    void init();
    void destroy();

    /*
     * Find a route to a node in subnetwork
     */
    PASER_routing_entry *findAdd(struct in_addr addr);

    /*
     * Find a routing entry given the destination address
     */
    PASER_routing_entry *findDest(struct in_addr dest_addr);

    /**
     * Get a list of all routes with a given next hop IP address
     */
    std::list<PASER_routing_entry*> getListWithNextHop(struct in_addr nextHop);

    /**
     * Insert a new entry to the map
     */
    PASER_routing_entry *insert(struct in_addr dest_addr, struct in_addr nxthop_addr, PASER_timer_packet * deltimer,
            PASER_timer_packet * validtimer, u_int32_t seqnum, u_int8_t hopcnt, u_int8_t is_gw, std::list<address_range> AddL,
            u_int8_t *Cert);

    /**
     * Update a entry in the map
     *
     *@param entry Pointer to the entry which will be updated.
     *@param dest_addr IP address of the node
     *@param nxthop_addr IP address of the next hop node
     *@param deltimer Pointer to delete Timeout
     *@param validtimer Pointer to valid Timeout
     *@param seqnum Sequence number of the node
     *@param hopcnt Metric to the node
     *@param is_gw Is the node a gateway
     *@param AddL Address range list of the node
     *@param Cert Certificate of the node
     *
     *@return Pointer to updated entry
     */
    PASER_routing_entry *update(PASER_routing_entry *entry, struct in_addr dest_addr, struct in_addr nxthop_addr,
            PASER_timer_packet * deltimer, PASER_timer_packet * validtimer, u_int32_t seqnum, u_int8_t hopcnt, u_int8_t is_gw,
            std::list<address_range> AddL, u_int8_t *Cert);

    /**
     * Delete a entry from the map.
     *
     *@param entry Pointer to the entry which will be deleted.
     */
    void delete_entry(PASER_routing_entry *entry);

    /**
     * Get the shortest Route to Gateway.
     *
     *@return Route to the Gateway or NULL if no Route to Gateway are given.
     */
    PASER_routing_entry *getRouteToGw();

    /**
     * Get the shortest Route to Gateway.
     *
     *@return Route to the Gateway or NULL if no Route to Gateway are given.
     */
    PASER_routing_entry *findBestGW();

    /**
     * Add a route to kernel routing table.
     *
     *@param dest_addr IP address of the destination node
     *@param forw_addr IP address of the next hop node
     *@param netmask Network mask of the destination node
     *@param metric Metric to the node
     *@param del_entry if true then the route will be deleted from the kernel table. Else a new route will be addes to the kernel table.
     *@param ifIndex Interface over which the node is reachable.
     */
    void updateKernelRoutingTable(struct in_addr dest_addr, struct in_addr forw_addr, struct in_addr netmask, u_int32_t metric,
            bool del_entry, int ifIndex);

    /**
     * Insert or update a entry in the routing table.
     * If a entry not exist then a new entry will be added to the table.
     * The delete and valid timer of the entry will be reseted.
     *
     *@param addList Address range list of the node
     *@param src_addr IP address of the node which entry will be updated.
     *@param seq Sequence number of the node
     *@param cert Certificate of the node
     *@param nextHop IP address of the next hop node
     *@param metric Metric to the node
     *@param ifIndex Interface over which the node is reachable.
     *@param now Current time
     *@param gFlag Is the node a gateway
     *@param trusted Is the Route trusted
     */
    void updateRoutingTableAndSetTableTimeout(std::list<address_range> addList, struct in_addr src_addr, uint32_t seq, X509 *cert,
            struct in_addr nextHop, u_int8_t metric, int ifIndex, struct timeval now, u_int8_t gFlag, bool trusted);

    /**
     * Reset the delete and valid timer of an entry.
     * If a entry not exist then a new entry will be NOT added.
     */
    void updateRoutingTableTimeout(struct in_addr src_addr, struct timeval now, int ifIndex);

    /**
     * Update the sequence number, delete and valid timer of an entry.
     * If a entry not exist then a new entry will be NOT added.
     */
    void updateRoutingTableTimeout(struct in_addr src_addr, u_int32_t seq, struct timeval now);

    /**
     * Insert or update a routes to the nodes from a given list.
     *
     *@param now Current time
     *@param addList A list of a nodes to which a routes will be updated
     *@param nextHop IP of the next hop node to the nodes from "addList"
     *@param ifIndex Interface over which the nodes are reachable.
     */
    void updateRoutingTable(struct timeval now, std::list<address_list> addList, struct in_addr nextHop, int ifIndex);

    /**
     * Delete all nodes from routing, neighbor and kernel routing tables and theirs timers
     * which follow over the given IP address.
     *
     *@param nextHop IP address
     */
    void deleteFromKernelRoutingTableNodesWithNextHopAddr(struct in_addr nextHop);

    /**
     * Update a valid and delete timer of a route to a given IP address
     */
    void updateRouteLifetimes(struct in_addr dest_addr);

    /**
     * Update or add the neighbor entry to IP addresses from a list and
     * update or add the routing to all subnetworks from a list.
     * The entry will be added with the metric equal to 1.
     */
    void updateNeighborFromHELLO(address_list liste, u_int32_t seq, int ifIndex);

    /**
     * Update or add the routing entry to all IP addresses from a list.
     * All entries will be added with the metric equal to 2.
     */
    void updateRouteFromHELLO(address_list liste, int ifIndex, struct in_addr nextHop);

    /**
     * Get all neighbor nodes and set own IP address in the list
     * to IP address of given Interface.
     */
    std::list<address_list> getNeighborAddressList(int ifNr);

//    /**
//     * The function checks whether all certificates in routing tables are valid.
//     * All routes, nodes and neighbors that have an invalid certificates will be deleted.
//     *
//     *@return 1 if a valid Route to gateway is given. Else 0.
//     */
//    int checkAllCert();

    /**
     * Clear Routing table and free all allocated memory
     */
    void clearTable();

    int getSize() {
        return route_table.size();
    }
    std::string shortInfo();
    std::string detailedInfo();

private:

};

#endif /* PASER_ROUTING_TABLE_H_ */
