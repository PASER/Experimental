/**
 *\class  		PASER_neighbor_table
 *@brief       	Class provides a map of node's neighbors.
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

class PASER_neighbor_table;

#ifndef PASER_NEIGHBOR_TABLE_H_
#define PASER_NEIGHBOR_TABLE_H_

#include <map>
#include <list>

#include "../config/PASER_defs.h"
#include "PASER_neighbor_entry.h"
#include "../config/PASER_global.h"
#include "../timer_management/PASER_timer_queue.h"

#include <sstream>
#include <stdlib.h>
#include <string.h>

#include "openssl/x509.h"

class PASER_neighbor_table {
private:
    /**
     * Map of node's neighbors.
     * Key   - IP address of the node.
     * Value - Pointer to the node's neighbor entry.
     */
    std::map<Uint128, PASER_neighbor_entry *> neighbor_table_map;

    PASER_timer_queue *timer_queue;
    PASER_global *pGlobal;

public:
    PASER_neighbor_table(PASER_global *paser_global);
    ~PASER_neighbor_table();
    /**
     * Find a routing entry given the destination address
     */
    PASER_neighbor_entry *findNeigh(struct in_addr neigh_addr);

    /**
     * Insert a new entry to the map
     *
     *@param neigh_addr IP address of the neighbor
     *@param deleteTimer Pointer to delete Timeout
     *@param validTimer Pointer to valid Timeout
     *@param neighFlag Is neighbor trusted
     *@param root Root element of the neighbor
     *@param IV Initial vector of the neighbor
     *@param position Geo Position of the neighbor
     *@param Cert Certificate of the neighbor
     *@param ifIndex Index of the network device on with the neighbor is available
     *
     *@return Pointer to inserted entry
     */
    PASER_neighbor_entry *insert(struct in_addr  neigh_addr,
                                PASER_timer_packet * deleteTimer,
                                PASER_timer_packet * validTimer,
                                int neighFlag,
                                u_int8_t *root,
                                u_int32_t IV,
                                geo_pos position,
                                u_int8_t *Cert,
                                u_int32_t ifIndex);

    /**
     * Update a entry in the map
     *
     *@param entry Pointer to the entry which will be updated.
     *@param neigh_addr IP address of the neighbor
     *@param deleteTimer Pointer to delete Timeout
     *@param validTimer Pointer to valid Timeout
     *@param neighFlag Is neighbor trusted
     *@param root Root element of the neighbor
     *@param IV Initial vector of the neighbor
     *@param position Geo Position of the neighbor
     *@param Cert Certificate of the neighbor
     *@param ifIndex Index of the network device on with the neighbor is available
     *
     *@return Pointer to updated entry
     */
    PASER_neighbor_entry *update(PASER_neighbor_entry *entry,
                                struct in_addr  neigh_addr,
                                PASER_timer_packet * deleteTimer,
                                PASER_timer_packet * validTimer,
                                int neighFlag,
                                u_int8_t *root,
                                u_int32_t IV,
                                geo_pos position,
                                u_int8_t *Cert,
                                u_int32_t ifIndex);

    /**
     * Delete a entry from the map.
     *
     *@param entry Pointer to the entry which will be deleted.
     */
    void delete_entry(PASER_neighbor_entry *entry);

    /**
     * Insert or update a entry in the neighbor table.
     * If a entry not exist then a new entry will be added to the table.
     * The delete and valid timer of the entry will be reseted.
     *
     *@param neigh IP address of the node which entry will be updated.
     *@param nFlag Is neighbor trusted
     *@param root Root element of the neighbor
     *@param iv Initial vector of the neighbor
     *@param position Geo Position of the neighbor
     *@param cert Certificate of the neighbor
     *@param now Current time
     *@param ifIndex Index of the network device on with the neighbor is available
     */
    void updateNeighborTableAndSetTableTimeout(struct in_addr neigh, int nFlag, u_int8_t *root, int iv, geo_pos position, X509 *cert, struct timeval now, u_int32_t ifIndex);

    /**
     * Reset the delete and valid timer of an entry.
     * If a entry not exist then a new entry will be NOT added.
     */
    void updateNeighborTableTimeout(struct in_addr neigh, struct timeval now);

    /**
     * Update IV of the entry and mark the entry as valid.
     * If a entry not exist then a new entry will be NOT added.
     */
    void updateNeighborTableIVandSetValid(struct in_addr neigh, u_int32_t IV);

    /**
     * Update IV of the entry.
     * If a entry not exist then a new entry will be NOT added.
     */
    void updateNeighborTableIV(struct in_addr neigh, u_int32_t IV);

    /**
     * The function checks whether all certificates in neighbor tables are valid.
     * All routes, nodes and neighbors that have an invalid certificates will be deleted.
     *
     *@return 1 if a valid Route to gateway is given. Else 0.
     */
    int checkAllCert();

    /**
     * Clear Neighbor table and free all allocated memory
     */
    void clearTable();

    std::string shortInfo();
    std::string detailedInfo();

    int getNeighborTableSize(){return neighbor_table_map.size();}
};

#endif /* PASER_NEIGHBOR_TABLE_H_ */
