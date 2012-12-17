/**
 *\class  		PASER_MSG
 *@brief       	Class (abstract) that defines the common features of all PASER packets.
 *@ingroup		PS
 *\authors    	Eugen.Paul | Mohamad.Sbeiti \@paser.info
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

#ifndef PASER_MSG_H_
#define PASER_MSG_H_

#include "../config/PASER_defs.h"
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <iomanip>

/*
 * Type of PASER packets
 */
enum packet_type {
    UB_RREQ = 0,
    UU_RREP = 1,
    TU_RREQ = 2,
    TU_RREP = 3,
    TU_RREP_ACK = 4,
    B_RERR = 5,
    B_HELLO = 6,
    B_ROOT = 7,
    B_RESET = 8,
    GTKREQ = 9,
    GTKREP = 10,
    GTKRESET = 11
};

class PASER_MSG {
public:
    packet_type type; ///< Type of PASER packets
    struct in_addr srcAddress_var; ///< IP address of source node
    struct in_addr destAddress_var; ///< IP address of destination node
    u_int32_t seq; ///< Sending node's current sequence number

public:
    PASER_MSG();
    virtual ~PASER_MSG();

    /**
     * Produces a multi-line description of the packet's contents.
     */
    virtual std::string detailedInfo() const=0;

    /**
     * Creates and returns an exact copy of this object.
     */
    virtual PASER_MSG *dup() const=0;

    /**
     * Creates and return an array of all fields that must be secured with hash or signature
     *
     *@param l length of created array
     *@return packet array
     */
    virtual uint8_t *toByteArray(int *l)=0;

    /**
     * Creates and return an array of all fields of the package
     *
     *@param l length of created array
     *@return packet array
     */
    virtual uint8_t *getCompleteByteArray(int *l)=0;
};

#endif /* PASER_MSG_H_ */
