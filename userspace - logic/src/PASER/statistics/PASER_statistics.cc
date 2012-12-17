/**
 *\class  		PASER_statistics
 *@brief       	Class provides functions for working with PASERs scheduler.
 *
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

#include "PASER_statistics.h"

#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <string>
#include <time.h>

#include "../../../defs.h"
#include "../config/PASER_defs.h"

PASER_statistics::PASER_statistics(PASER_global *paser_global) {
    pGlobal = paser_global;

    broatcastPackets = 0;
    unicastPackets = 0;
    sendbytes = 0;

    RoutingAdd = NULL;
    RoutingDelete = NULL;
    RoutingBreak = NULL;
    RoutingTimeout = NULL;

    if (PASER_LOG_ROUTE_MODIFICATION_ADD)
        RoutingAdd = fopen(PASERD_ROUTE_ADD_LOG_FILE, "w");
    if (PASER_LOG_ROUTE_MODIFICATION_DELETE)
        RoutingDelete = fopen(PASERD_ROUTE_DELETE_LOG_FILE, "w");
    if (PASER_LOG_ROUTE_MODIFICATION_BREAK)
        RoutingBreak = fopen(PASERD_ROUTE_BREAK_LOG_FILE, "w");
    if (PASER_LOG_ROUTE_MODIFICATION_TIMEOUT)
        RoutingTimeout = fopen(PASERD_ROUTE_TIMEOUT_LOG_FILE, "w");
    logfile = fopen(PASERD_OVERHEAD_LOG_FILE, "w");

}

PASER_statistics::~PASER_statistics() {
    if (logfile) {
        fprintf(logfile, "%d\t%d\t%ld\n", broatcastPackets, unicastPackets, sendbytes);
        fclose(logfile);
    }
    if (RoutingAdd)
        fclose(RoutingAdd);
    if (RoutingDelete)
        fclose(RoutingDelete);
    if (RoutingTimeout)
        fclose(RoutingTimeout);
}

void PASER_statistics::routingTableModificationAdd(in_addr destAddr, in_addr nextHopAddr) {
    if (RoutingAdd) {
        time_t rawtime;
        time(&rawtime);

        char str[50];
        strcpy(str, ctime(&rawtime));
        str[strlen(str) - 1] = '\0';

        fprintf(RoutingAdd, "%s add  %15s ", str, inet_ntoa(destAddr));
        fprintf(RoutingAdd, "over  %s\n", inet_ntoa(nextHopAddr));
    }
}

void PASER_statistics::routingTableModificationDelete(in_addr destAddr) {
    if (RoutingDelete) {
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);

        fprintf(RoutingDelete, "%s\t%s\n", asctime(timeinfo), inet_ntoa(destAddr));
    }
}

void PASER_statistics::routingTableModificationBreak(in_addr destAddr) {
    if (RoutingBreak) {
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);

        fprintf(RoutingBreak, "%s\t%s\n", asctime(timeinfo), inet_ntoa(destAddr));
    }
}

void PASER_statistics::routingTableModificationTimeout(in_addr destAddr) {
    if (RoutingTimeout) {
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);

        fprintf(RoutingTimeout, "%s\t%s\n", asctime(timeinfo), inet_ntoa(destAddr));
    }
}

void PASER_statistics::incBroadcastPackets() {
    broatcastPackets++;
}
void PASER_statistics::incUnicastPackets() {
    unicastPackets++;
}
void PASER_statistics::addToSendBytes(long s) {
    sendbytes += s;
}
