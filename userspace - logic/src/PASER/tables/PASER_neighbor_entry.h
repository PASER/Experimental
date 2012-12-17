/**
 *\class  		PASER_neighbor_entry
 *@brief       	Class represents an entry in the neighbor table
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

#ifndef PASER_NEIGHBOR_ENTRY_H_
#define PASER_NEIGHBOR_ENTRY_H_

#include "../config/PASER_defs.h"
#include "../timer_management/PASER_timer_packet.h"
#include <sstream>
#include <stdlib.h>
#include <string.h>

class PASER_neighbor_entry{
public:
    ~PASER_neighbor_entry();
    PASER_timer_packet * deleteTimer;       ///< Pointer to the delete timer
    PASER_timer_packet * validTimer;        ///< Pointer to the valid timer
    struct in_addr  neighbor_addr;          ///< IP address of the neighbor
    int neighFlag;                          ///< Reflects the trust relation between a neighbor and that node
    u_int8_t *root;                         ///< Pointer to the root element of the neighbor
    u_int32_t IV;                           ///< IV of the neighbor
    geo_pos position;                       ///< Geo position of the neighbor
    u_int8_t *Cert;                         ///< Certificate of the neighbor
    u_int8_t isValid;                       ///< Is the route to the neighbor fresh/valid
    u_int32_t ifIndex;                      ///< Interface over which the neighbor is reachable

    /**
     * Set <b>validTimer</b>.
     * Old validTimer will be not freed.
     */
    void setValidTimer(PASER_timer_packet *_validTimer);

    std::string detailedInfo();
};

#endif /* PASER_NEIGHBOR_ENTRY_H_ */
