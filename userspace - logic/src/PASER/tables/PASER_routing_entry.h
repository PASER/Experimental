/**
 *\class  		PASER_routing_entry
 *@brief       	Class represents an entry in the routing table
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

#ifndef PASER_ROUTING_ENTRY_H_
#define PASER_ROUTING_ENTRY_H_

#include <list>

#include "../timer_management/PASER_timer_packet.h"

#include <sstream>
#include <stdlib.h>
#include <string.h>

class PASER_routing_entry{
public:
    struct in_addr  dest_addr;              ///< IP address of the node
    struct in_addr  nxthop_addr;            ///< IP address of the next hop
    PASER_timer_packet * deleteTimer;       ///< Pointer to the delete timer
    PASER_timer_packet * validTimer;        ///< Pointer to the valid timer
    u_int32_t   seqnum;                     ///< Sequence number of the node
    u_int8_t    hopcnt;                     ///< Metric of the route
    u_int8_t    is_gw;                      ///< is the node a Gateway

    u_int8_t    isValid;                    ///< Is the route to the node fresh/valid

    std::list<address_range> AddL;          ///< IP Addresses of the node's subnetworks
    u_int8_t *Cert;                         ///< Certificate of the node

public:
    ~PASER_routing_entry();
    bool operator==(PASER_routing_entry ent);

    /**
     * Set <b>validTimer</b>.
     * Old validTimer will be not freed.
     */
    void setValidTimer(PASER_timer_packet *_validTimer);

    std::string detailedInfo();
};

#endif /* PASER_ROUTING_ENTRY_H_ */
