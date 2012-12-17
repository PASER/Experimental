/**
 *\class  		PASER_route_maintenance
 *@brief       	Class provides functions for working with PASER timers and Link Layer Feedback.
 *@ingroup		RM
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

class PASER_route_maintenance;

#ifndef PASER_ROUTE_MAINTENANCE_H_
#define PASER_ROUTE_MAINTENANCE_H_

#include "../config/PASER_defs.h"
#include "../config/PASER_global.h"
#include "../config/PASER_config.h"
#include "../timer_management/PASER_timer_packet.h"

class PASER_route_maintenance {
public:
    PASER_route_maintenance(PASER_global *paser_global);

    /**
     * These are timeout functions which are called when
     * timers expire. Get the next timer and checks the
     * type to the necessary conversions and call the
     * corresponding functions to handle the information.
     */
    void handleSelfMsg();

    /**
     * Process a link layer feedback. Delete unreachable routes
     * from routing and neighbor tables.
     *
     *@param src not used
     *@param dest IP address to which the route has been broken
     *@param sendRERR should the RERR message be send
     */
    void packetFailed(struct in_addr src, struct in_addr dest, bool sendRERR);

private:
    PASER_global *pGlobal;
    PASER_config *paser_configuration;

    void timeout_KDC_request(PASER_timer_packet *t);
    void timeout_ROUTE_DISCOVERY_UB(PASER_timer_packet *t);
    void timeout_ROUTINGTABLE_DELETE_ENTRY(PASER_timer_packet *t);
    void timeout_ROUTINGTABLE_NO_VALID_ENTRY(PASER_timer_packet *t);
    void timeout_NEIGHBORTABLE_DELETE_ENTRY(PASER_timer_packet *t);
    void timeout_NEIGHBORTABLE_NO_VALID_ENTRY(PASER_timer_packet *t);
    void timeout_TU_RREP_ACK_TIMEOUT(PASER_timer_packet *t);
    void timeout_HELLO_SEND_TIMEOUT(PASER_timer_packet *t);
    void timeout_ROOT_TIMEOUT(PASER_timer_packet *t);
    void timeout_SSL_TIMEOUT(PASER_timer_packet *t);

};

#endif /* PASER_ROUTE_MAINTENANCE_H_ */
