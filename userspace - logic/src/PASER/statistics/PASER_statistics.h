/**
 *\class  		PASER_statistics
 *@brief        Class provides functions for working with PASERs scheduler.
 *@ingroup 		Statistics
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

class PASER_statistics;

#ifndef PASERSTATISTICS_H_
#define PASERSTATISTICS_H_


#include <stdio.h>
#include "../config/PASER_global.h"

class PASER_statistics {
public:
    PASER_statistics(PASER_global *paser_global);
    virtual ~PASER_statistics();

    void routingTableModificationAdd(in_addr destAddr, in_addr nextHopAddr);
    void routingTableModificationTimeout(in_addr destAddr);
    void routingTableModificationBreak(in_addr destAddr);
    void routingTableModificationDelete(in_addr destAddr);

    void incBroadcastPackets();
    void incUnicastPackets();
    void addToSendBytes(long s);
private:
    PASER_global *pGlobal;

    int broatcastPackets;
    int unicastPackets;
    long sendbytes;

    FILE *RoutingAdd;
    FILE *RoutingTimeout;
    FILE *RoutingDelete;
    FILE *RoutingBreak;
    FILE *logfile;

};

#endif /* PASERSTATISTICS_H_ */
