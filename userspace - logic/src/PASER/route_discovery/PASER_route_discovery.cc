/**
 *\class  		PASER_route_discovery
 *@brief       	Class provides functions to start a registration or route discovery.
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

#include "../config/PASER_defs.h"
#include "PASER_route_discovery.h"

PASER_route_discovery::PASER_route_discovery(PASER_global *paser_global) {
    pGlobal = paser_global;
}

void PASER_route_discovery::tryToRegister() {
    if (pGlobal->getIsRegistered()) {
        return;
    }
    if (pGlobal->getWasRegistered() && !pGlobal->getPaser_configuration()->isGWsearch()) {
        return;
    }
    struct in_addr bcast_addr;
    bcast_addr.s_addr = (in_addr_t) 0xFFFFFFFF;
    route_discovery(bcast_addr, 1);
}

void PASER_route_discovery::route_discovery(struct in_addr dest_addr, int isDestGW) {
    // If we are already doing a route discovery for dest_addr,
    // then simply return
    if (pGlobal->getRreq_list()->pending_find(dest_addr)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Route request to %s is already send.\n", inet_ntoa(dest_addr));
        return;
    }

    PASER_UB_RREQ *packet = NULL;
    if (isDestGW) {
        pGlobal->generateGwSearchNonce();
    }
    for (u_int32_t i = 0; i < pGlobal->getPaser_configuration()->getNetDeviceNumber(); i++) {
        in_addr WlanAddrStruct;
        WlanAddrStruct.s_addr = pGlobal->getPaser_configuration()->getNetDevice()[i].ipaddr.s_addr;
        if (packet != NULL) {
            delete packet;
        }
        packet = pGlobal->getPacketSender()->send_ub_rreq(WlanAddrStruct, dest_addr, isDestGW);
    }
    pGlobal->incSeqNr();

    if (packet == NULL)
        return;
    // Record information for destination
    packet_rreq_entry *pend_rreq = pGlobal->getRreq_list()->pending_add(dest_addr);

    PASER_timer_packet *tPack = new PASER_timer_packet();
    tPack->data = (void *) packet;
    tPack->destAddr.s_addr = dest_addr.s_addr;
    tPack->handler = ROUTE_DISCOVERY_UB;
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    tPack->timeout = timeval_add(now, PASER_UB_RREQ_WAIT_TIME);
    pend_rreq->tries = 0;

    pGlobal->getTimer_queue()->timer_add(tPack);
    pend_rreq->tPack = tPack;
}

void PASER_route_discovery::processPacket(struct in_addr src_addr, struct in_addr dest_addr) {
    if (!pGlobal->getWasRegistered()) {
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Route discovery. Dest:%s", inet_ntoa(dest_addr));
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTE_DISCOVERY, " Src:%s.\n", inet_ntoa(src_addr));
    bool isLocal = false;

    isLocal = pGlobal->getPaser_configuration()->isAddInMyLocalAddress(src_addr);

    if (!isLocal && pGlobal->getPaser_configuration()->isAddInMyLocalAddress(src_addr)) {
        isLocal = true;
    }

    // look up routing table entry for packet destination
    PASER_routing_entry *rEntry = pGlobal->getRouting_table()->findDest(dest_addr);
    bool isRoute = false;
    // a valid route exists
    if (rEntry == NULL) {
    } else if (rEntry->isValid) {
        PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(rEntry->nxthop_addr);
        if (nEntry == NULL || !nEntry->neighFlag || !nEntry->isValid) {
            isRoute = false;
        } else {
            isRoute = true;
        }
    }
    // no route in the table found -> route discovery (if none is already underway)
    if (!isRoute) {
        if (isLocal
                || (rEntry && pGlobal->getPaser_configuration()->isLocalRepair()
                        && pGlobal->getPaser_configuration()->getMaxLocalRepairHopCount() >= rEntry->hopcnt)) {
            // start route discovery
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Try to start route discovery. Dest: %s,", inet_ntoa(dest_addr));
            PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTE_DISCOVERY, " Src: %s.\n", inet_ntoa(src_addr));
            route_discovery(dest_addr, 0);
        } else {
            // cann't start route discovery => send RERR
            std::list<unreachableBlock> allAddrList;
            unreachableBlock temp;
            temp.addr.s_addr = dest_addr.s_addr;
            temp.seq = 0;
            allAddrList.push_back(temp);
            // send RERR
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Try to send RRER. Dest: %s,", inet_ntoa(dest_addr));
            PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTE_DISCOVERY, " Src: %s.\n", inet_ntoa(src_addr));
            pGlobal->getPacketSender()->send_rerr(allAddrList);

            struct timeval now;
            pGlobal->getPASERtimeofday(&now);
            // Add destination IP to black list
            pGlobal->getBlacklist()->setRerrTime(dest_addr, now);
        }
    } else {
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Route to Dest: %s exists.\n", inet_ntoa(dest_addr));
        // send packets
        in_addr br;
        br.s_addr = PASER_ALLONES_ADDRESS_MASK;
        pGlobal->getPASER_socket()->releaseQueue(dest_addr, br);
    }
}
