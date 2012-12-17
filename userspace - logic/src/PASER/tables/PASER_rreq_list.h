/**
 *\class  		PASER_rreq_list
 *@brief		Class implements the RREQ list.
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

#ifndef PASER_RREQ_LIST_H_
#define PASER_RREQ_LIST_H_


#include <map>
#include "../config/PASER_defs.h"
#include "../timer_management/PASER_timer_packet.h"

#include <sstream>
#include <stdlib.h>
#include <string.h>

/*
 * The class represents an entry in the RREQ list
 */
class packet_rreq_entry {
public:
    int tries;
    struct in_addr dest_addr;
    PASER_timer_packet *tPack;

    ~packet_rreq_entry(){

    }
};

/**
 * Implementation of the RREQ list.
 * Here we maintain a map of those RREQs which
 * haven't been answered with a RREP yet
 * or a map of those RREPs which
 * haven't been answered with a RREP-ACK yet
 */
class PASER_rreq_list
{
private:
    /**
     * Map of RREQ/RREP
     * Key   - Destination IP Address
     * Value - Pointer to entry
     */
    std::map<Uint128, packet_rreq_entry * > rreq_list;

public:
    ~PASER_rreq_list();

    /*
     * Add a new entry to the list
     */
    packet_rreq_entry *pending_add(struct in_addr dest_addr);

    /*
     * Remove an entry from the list
     */
    int pending_remove(packet_rreq_entry *entry);

    /*
     * Find an entry in the list with the given destination address
     */
    packet_rreq_entry *pending_find(struct in_addr dest_addr);

    /*
     * Find an entry in the list with the given destination address and network mask
     */
    packet_rreq_entry* pending_find_addr_with_mask(struct in_addr dest_addr, struct in_addr dest_mask);

    /**
     * Clear Routing table and free all allocated memory
     */
    void clearTable();

    int getSize() {
        return rreq_list.size();
    }

    std::string detailedInfo();
};

#endif /* PASER_RREQ_LIST_H_ */
