/**
 *\class  		PASER_timer_packet
 *@brief       	Class represents an entry in the timer queue
 *@ingroup 		TM
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

#ifndef PASER_TIMER_PACKET_H_
#define PASER_TIMER_PACKET_H_

#include "../config/PASER_defs.h"

enum timeout_var{
    KDC_REQUEST,
	ROUTE_DISCOVERY_UB,
	ROUTINGTABLE_DELETE_ENTRY,
	ROUTINGTABLE_VALID_ENTRY,
	NEIGHBORTABLE_DELETE_ENTRY,
	NEIGHBORTABLE_VALID_ENTRY,
	TU_RREP_ACK_TIMEOUT,
	HELLO_SEND_TIMEOUT,
	PASER_ROOT,
	SSL_timer
};

class PASER_timer_packet{
public:
    struct timeval timeout;     ///< Time when the timeout expires
    struct in_addr destAddr;    ///< IP address of a node
    timeout_var handler;        ///< Type of timeout
    void *data;                 ///< pointer to data
    int32_t sslFD;              ///< Socket

public:
    PASER_timer_packet();
    ~PASER_timer_packet();

    bool operator==(PASER_timer_packet *op2);

};

#endif /* PASER_TIMER_PACKET_H_ */
