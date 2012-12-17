/**
 *\class  		PASER_route_discovery
 *@brief 		Class provides functions to start a registration or route discovery.
 *@ingroup		RD
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

class PASER_route_discovery;

#ifndef PASER_ROUTE_DISCOVERY_H_
#define PASER_ROUTE_DISCOVERY_H_

#include "../config/PASER_global.h"
#include "../config/PASER_config.h"

class PASER_route_discovery {

private:
    PASER_global *pGlobal;

public:
    PASER_route_discovery(PASER_global *paser_global);

    /**
     * Start registration.
     * If the node is unregistered the registration will be started.
     */
    void tryToRegister();

    /**
     * Start route discovery.
     * The route discovery will be started only if the route discovery is not already started.
     *
     *@param dest_addr IP address of destination node or broadcast if <b>isDestGW</b> is set.
     *@param isDestGW is set if route to a gateway must be found.
     */
    void route_discovery(struct in_addr dest_addr, int isDestGW);

    /**
     * Process a data packet. If the route to the destination node is not known,
     * then route discovery is started.
     *
     *@param src_addr IP address of the source node
     *@param dest_addr IP address of the destination node
     */
    void processPacket(struct in_addr src_addr, struct in_addr dest_addr);

};

#endif /* PASER_ROUTE_DISCOVERY_H_ */
