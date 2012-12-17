/**
 *\class  		PASER_route_maintenance
 *@brief       	Class provides functions for working with PASER timers and Link Layer Feedback.
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

#include "PASER_route_maintenance.h"
#include "../config/PASER_defs.h"
#include "../packet_structure/PASER_TB_RERR.h"

PASER_route_maintenance::PASER_route_maintenance(PASER_global *paser_global) {
    pGlobal = paser_global;
    paser_configuration = pGlobal->getPaser_configuration();
}

void PASER_route_maintenance::handleSelfMsg() {
    PASER_timer_packet *nextTimout = pGlobal->getTimer_queue()->timer_get_next_timer();
    if (!nextTimout) {
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "No timeout to process.\n");
        return;
    }
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    if (now.tv_sec < nextTimout->timeout.tv_sec) {
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout has not expired.\n");
        return;
    }
    if (now.tv_sec == nextTimout->timeout.tv_sec && now.tv_usec < nextTimout->timeout.tv_usec) {
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout has not expired(2).\n");
        return;
    }

    if (nextTimout != NULL) {
        switch (nextTimout->handler) {
        case KDC_REQUEST:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: KDC_REQUEST\n");
            timeout_KDC_request(nextTimout);
            break;
        case ROUTE_DISCOVERY_UB:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: ROUTE_DISCOVERY_UB\n");
            timeout_ROUTE_DISCOVERY_UB(nextTimout);
            break;
        case ROUTINGTABLE_DELETE_ENTRY:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: ROUTINGTABLE_DELETE_ENTRY\n");
            timeout_ROUTINGTABLE_DELETE_ENTRY(nextTimout);
            break;
        case ROUTINGTABLE_VALID_ENTRY:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: ROUTINGTABLE_VALID_ENTRY\n");
            timeout_ROUTINGTABLE_NO_VALID_ENTRY(nextTimout);
            break;
        case NEIGHBORTABLE_DELETE_ENTRY:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: NEIGHBORTABLE_DELETE_ENTRY\n");
            timeout_NEIGHBORTABLE_DELETE_ENTRY(nextTimout);
            break;
        case NEIGHBORTABLE_VALID_ENTRY:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: NEIGHBORTABLE_VALID_ENTRY\n");
            timeout_NEIGHBORTABLE_NO_VALID_ENTRY(nextTimout);
            break;
        case TU_RREP_ACK_TIMEOUT:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: TU_RREP_ACK_TIMEOUT\n");
            timeout_TU_RREP_ACK_TIMEOUT(nextTimout);
            break;
        case HELLO_SEND_TIMEOUT:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: HELLO_SEND_TIMEOUT\n");
            timeout_HELLO_SEND_TIMEOUT(nextTimout);
            break;
        case PASER_ROOT:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: PASER_ROOT\n");
            timeout_ROOT_TIMEOUT(nextTimout);
            break;
        case SSL_timer:
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Timeout: SSL_timer\n");
            timeout_SSL_TIMEOUT(nextTimout);
            break;
        }
    }
}

void PASER_route_maintenance::timeout_KDC_request(PASER_timer_packet *t) {
    if (pGlobal->getIsRegistered() == false) {
        lv_block cert;
        if (!pGlobal->getCrypto_sign()->getCert(&cert)) {
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Cann't read own certificate. KDC Request will be not sent.\n");
            return;
        }
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Send KDC Request.\n");
        pGlobal->getPacketSender()->sendKDCRequest(paser_configuration->getNetDevice()[0].ipaddr,
                paser_configuration->getNetDevice()[0].ipaddr, cert, pGlobal->getLastGwSearchNonce());
        free(cert.buf);
        t->timeout = timeval_add(t->timeout, PASER_KDC_REQUEST_TIME);
        pGlobal->getTimer_queue()->timer_sort();
    }
    return;
}

void PASER_route_maintenance::timeout_ROUTE_DISCOVERY_UB(PASER_timer_packet *t) {
    PASER_UB_RREQ * packet = (PASER_UB_RREQ *) t->data;
    if (!packet) {
        pGlobal->getTimer_queue()->timer_remove(t);
        delete t;
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Cann't read UB_RREQ packet from timer. UB-RREQ will be not sent.\n");
        return;
    }

    packet_rreq_entry *pend_rreq = pGlobal->getRreq_list()->pending_add(t->destAddr);
    if (!pend_rreq) {
        pGlobal->getTimer_queue()->timer_remove(t);
        delete t;
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Cann't get request info. UB-RREQ will be not sent.\n");
        return;
    }
    if (pend_rreq->tries < PASER_UB_RREQ_TRIES || (packet->GFlag && !pGlobal->getWasRegistered())) {
        if (packet->GFlag && !pGlobal->getWasRegistered()) {

        } else {
            pend_rreq->tries++;
        }
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "pend_rreq->tries: %d, GFlag = %d\n", pend_rreq->tries, (int)packet->GFlag);
        packet->seq = pGlobal->getSeqNr();
        packet->seqForw = pGlobal->getSeqNr();
        //send broadcast on all interfaces
        for (u_int32_t i = 0; i < paser_configuration->getNetDeviceNumber(); i++) {
            PASER_UB_RREQ *packetToSend = new PASER_UB_RREQ(*packet);
            struct timeval now;
            pGlobal->getPASERtimeofday(&now);
            packetToSend->timestamp = now.tv_sec;
            packetToSend->srcAddress_var.s_addr = paser_configuration->getNetDevice()[i].ipaddr.s_addr;
            packetToSend->AddressRangeList.clear();
            address_list tempAddList;
            tempAddList.ipaddr = paser_configuration->getNetDevice()[i].ipaddr;
            tempAddList.range = paser_configuration->getAddL();
            packetToSend->AddressRangeList.push_back(tempAddList);
            geo_pos myGeo = pGlobal->getGeoPosition();
            packetToSend->geoForwarding.lat = myGeo.lat;
            packetToSend->geoForwarding.lon = myGeo.lon;
            pGlobal->getCrypto_sign()->signUBRREQ(packetToSend);
            // send packet
            // update Timer
            struct in_addr bcast_addr;
            bcast_addr.s_addr = (in_addr_t) 0xFFFFFFFF;
//            paser_modul->send_packet(packetToSend, bcast_addr, paser_modul->MYgetWlanInterfaceIndexByAddress(packetToSend->srcAddress_var.S_addr));
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Send UB-RREQ on NetDivice: %s.\n", paser_configuration->getNetDevice()[i].ifname);
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Send Route RE-Request to Dest: %s, isGW: %d.\n",
                    inet_ntoa(packetToSend->destAddress_var), (int)packetToSend->GFlag);
            PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_INFO, "%s", packet->detailedInfo().c_str());
            //Convert packet object to byte array
            uint8_t *packetBuf;
            int packetLenth = 0;
            packetBuf = packetToSend->getCompleteByteArray(&packetLenth);
            if (!packetBuf) {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create UB-RREQ.\n");
                delete packet;
                continue;
            }
            //send byte array
            pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
                    &(paser_configuration->getNetDevice()[i]));

            delete packetToSend;
        }
        // segNr++
        pGlobal->incSeqNr();
        pGlobal->getPASERtimeofday(&(t->timeout));
        t->timeout = timeval_add(t->timeout, PASER_UB_RREQ_WAIT_TIME);
        pGlobal->getTimer_queue()->timer_sort();
        if (pGlobal->getPaser_configuration()->isResetHelloByBroadcast()) {
            pGlobal->resetHelloTimer();
        }
        return;
    }
    //remove timer
    PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Delete request.\n");
    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Route Request to IP: %s, isGW: %d will be deleted.\n",
            inet_ntoa(packet->destAddress_var), (int)packet->GFlag);
    pGlobal->getTimer_queue()->timer_remove(t);
    pGlobal->getRreq_list()->pending_remove(pend_rreq);
    // delete packets from queue
    in_addr br;
    br.s_addr = PASER_ALLONES_ADDRESS_MASK;
    pGlobal->getPASER_socket()->deleteQueue(t->destAddr, br);
    PASER_routing_entry *routeToGW = pGlobal->getRouting_table()->findBestGW();
    if (routeToGW == NULL && paser_configuration->isGWsearch() && !pGlobal->getWasRegistered()) {
        pGlobal->getRoute_findung()->tryToRegister();
    }
    delete pend_rreq;
    delete t;
}

void PASER_route_maintenance::timeout_ROUTINGTABLE_DELETE_ENTRY(PASER_timer_packet *t) {
    PASER_routing_entry *rEntry = pGlobal->getRouting_table()->findDest(t->destAddr);
    if (rEntry != NULL) {
        pGlobal->getRouting_table()->delete_entry(rEntry);
        PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(t->destAddr);
        if (nEntry != NULL) {
            pGlobal->getNeighbor_table()->delete_entry(nEntry);
            PASER_timer_packet* delTime = nEntry->deleteTimer;
            PASER_timer_packet* valTime = nEntry->validTimer;
            if (delTime) {
                pGlobal->getTimer_queue()->timer_remove(delTime);
                delete delTime;
            }
            if (valTime) {
                pGlobal->getTimer_queue()->timer_remove(valTime);
                delete valTime;
            }
            delete nEntry;
        }
        delete rEntry;
    }
    pGlobal->getTimer_queue()->timer_remove(t);
    delete t;
}

void PASER_route_maintenance::timeout_ROUTINGTABLE_NO_VALID_ENTRY(PASER_timer_packet *t) {
    struct in_addr destAddr = t->destAddr;
    PASER_routing_entry *rEntry = pGlobal->getRouting_table()->findDest(t->destAddr);
    if (rEntry != NULL) {
        rEntry->isValid = 0;
        rEntry->validTimer = NULL;
        PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(t->destAddr);
        if (nEntry != NULL) {
            PASER_timer_packet* valTime = nEntry->validTimer;
            if (valTime) {
                pGlobal->getTimer_queue()->timer_remove(valTime);
                delete valTime;
            }
            nEntry->validTimer = NULL;
        }
    }
    pGlobal->getTimer_queue()->timer_remove(t);
    delete t;
    // if the node a neighbor is make all Routes over the node invalid and delete it from kernel routing table
    pGlobal->getRouting_table()->deleteFromKernelRoutingTableNodesWithNextHopAddr(destAddr);
    PASER_routing_entry *routeToGW = pGlobal->getRouting_table()->findBestGW();
    if (routeToGW == NULL && !paser_configuration->getIsGW() && paser_configuration->isGWsearch() && !pGlobal->getWasRegistered()) {
        pGlobal->setIsRegistered(false);
        pGlobal->getRoute_findung()->tryToRegister();
    }
}

void PASER_route_maintenance::timeout_NEIGHBORTABLE_DELETE_ENTRY(PASER_timer_packet *t) {
    PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(t->destAddr);
    if (nEntry != NULL) {
        pGlobal->getNeighbor_table()->delete_entry(nEntry);
        delete nEntry;
    }
    pGlobal->getTimer_queue()->timer_remove(t);
    delete t;
}

void PASER_route_maintenance::timeout_NEIGHBORTABLE_NO_VALID_ENTRY(PASER_timer_packet *t) {
    struct in_addr destAddr = t->destAddr;
    PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(t->destAddr);
    if (nEntry != NULL) {
        nEntry->isValid = 0;
        nEntry->validTimer = NULL;
    }
    pGlobal->getTimer_queue()->timer_remove(t);
    delete t;
    // make all Routes over the neighbor invalid and delete it from kernel routing table
    pGlobal->getRouting_table()->deleteFromKernelRoutingTableNodesWithNextHopAddr(destAddr);
    PASER_routing_entry *routeToGW = pGlobal->getRouting_table()->findBestGW();
    if (routeToGW == NULL && !paser_configuration->getIsGW() && paser_configuration->isGWsearch() && !pGlobal->getWasRegistered()) {
        pGlobal->setIsRegistered(false);
        pGlobal->getRoute_findung()->tryToRegister();
    }
}

void PASER_route_maintenance::timeout_TU_RREP_ACK_TIMEOUT(PASER_timer_packet *t) {
    PASER_UU_RREP * packet = (PASER_UU_RREP *) t->data;
    if (!packet) {
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Cann't read UU-RREP packet from timer. UU-RREP will be not sent.\n");
        pGlobal->getTimer_queue()->timer_remove(t);
        delete t;
        return;
    }
    packet_rreq_entry *pend_rrep = pGlobal->getRrep_list()->pending_find(t->destAddr);
    if (pend_rrep == NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Cann't get request info. UU-RREP will be not sent.\n");
        pGlobal->getTimer_queue()->timer_remove(t);
        delete t;
        return;
    }
    if (pend_rrep->tries < PASER_UU_RREP_TRIES) {
        pend_rrep->tries++;
        if (paser_configuration->isAddInMyLocalAddress(packet->destAddress_var)) {
            packet->seq = pGlobal->getSeqNr();
            pGlobal->incSeqNr();
        }
        geo_pos myGeo = pGlobal->getGeoPosition();
        packet->geoForwarding.lat = myGeo.lat;
        packet->geoForwarding.lon = myGeo.lon;
        pGlobal->getCrypto_sign()->signUURREP(packet);
        PASER_UU_RREP *packetToSend = new PASER_UU_RREP(*packet);
        // update Timer
        PASER_routing_entry *rEntry = pGlobal->getRouting_table()->findDest(packetToSend->srcAddress_var);
        if (!rEntry) {
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Cann't find route to neighbor. UU-RREP will be not sent.\n");
            delete packetToSend;
            //remove timer
            pGlobal->getTimer_queue()->timer_remove(t);
            pGlobal->getRrep_list()->pending_remove(pend_rrep);
            delete pend_rrep;
            delete t;
            return;
        }
        PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(rEntry->nxthop_addr);
        if (!nEntry) {
            PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Cann't find neighbor. UU-RREP will be not sent.\n");
            delete packetToSend;
            //remove timer
            pGlobal->getTimer_queue()->timer_remove(t);
            pGlobal->getRrep_list()->pending_remove(pend_rrep);
            delete pend_rrep;
            delete t;
            return;
        }
        // send Packet
        //seqNr++
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Send UU-RREP.\n");
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Send Route Reply to IP: %s.\n", inet_ntoa(packetToSend->srcAddress_var));
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_INFO, "%s", packet->detailedInfo().c_str());
        //Convert packet object to byte array
        uint8_t *packetBuf;
        int packetLenth = 0;
        packetBuf = packetToSend->getCompleteByteArray(&packetLenth);
        if (!packetBuf) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREP-ACK.\n");
            delete packetToSend;
            return;
        }
        //send byte array
        pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, packetToSend->srcAddress_var, PASER_PORT,
                &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

        pGlobal->getPASERtimeofday(&(t->timeout));
        t->timeout = timeval_add(t->timeout, PASER_UU_RREP_WAIT_TIME);
        pGlobal->getTimer_queue()->timer_sort();
        delete packetToSend;
        return;
    }
    //remove timer
    PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Delete UU-RREP.\n");
    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Route Reply to IP: %s will be deleted.\n", inet_ntoa(packet->srcAddress_var));
    pGlobal->getTimer_queue()->timer_remove(t);
    pGlobal->getRrep_list()->pending_remove(pend_rrep);
    delete pend_rrep;
    delete t;
}

void PASER_route_maintenance::timeout_HELLO_SEND_TIMEOUT(PASER_timer_packet *t) {
    for (u_int32_t i = 0; i < paser_configuration->getNetDeviceNumber(); i++) {
        network_device *tempDevice = paser_configuration->getNetDevice();
        PASER_TB_HELLO *packetToSend = new PASER_TB_HELLO(tempDevice[i].ipaddr, pGlobal->getSeqNr());
        packetToSend->seq = pGlobal->getSeqNr();
        std::list<address_list> tempList = pGlobal->getRouting_table()->getNeighborAddressList(i);
//        for (std::list<address_list>::iterator it = tempList.begin(); it != tempList.end(); it++) {
//            address_list tempEntry;
//            tempEntry.ipaddr = ((address_list) *it).ipaddr;
//            std::list<address_range> tempRange;
//            for (std::list<address_range>::iterator it2 = tempRange.begin(); it2 != tempRange.end(); it2++) {
//                address_range tempR;
//                tempR.ipaddr = ((address_range) *it2).ipaddr;
//                tempR.mask = ((address_range) *it2).mask;
//                tempRange.push_back(tempR);
//            }
//            packetToSend->AddressRangeList.push_back(tempEntry);
//        }
        packetToSend->AddressRangeList.assign(tempList.begin(), tempList.end());

        if (packetToSend->AddressRangeList.size() <= 1) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Have no valid neighbors. HELLO will be not send.\n");
            delete packetToSend;
            continue;
        }

        geo_pos myGeo = pGlobal->getGeoPosition();
        packetToSend->geoQuerying.lat = myGeo.lat;
        packetToSend->geoQuerying.lon = myGeo.lon;

        int next_iv = 0;
        u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
        packetToSend->auth = pGlobal->getRoot()->getNextSecret(&next_iv, secret);
        //set new sequence number, because "root->getNextSecret" can increase it
        packetToSend->seq = pGlobal->getSeqNr();
        packetToSend->secret = secret;

        pGlobal->getCrypto_hash()->computeHmacHELLO(packetToSend, pGlobal->getGTK());

        // send packet
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0xFFFFFFFF;
        //Convert packet object to byte array
        uint8_t *packetBuf;
        int packetLenth = 0;
        packetBuf = packetToSend->getCompleteByteArray(&packetLenth);
        if (!packetBuf) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create HELLO.\n");
            delete packetToSend;
            return;
        }
        //send byte array
        pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
                &(paser_configuration->getNetDevice()[i]));

        //seqNr++
        pGlobal->incSeqNr();
        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Send HELLO.\n");
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_INFO, "%s", packetToSend->detailedInfo().c_str());
        delete packetToSend;
    }
    pGlobal->getPASERtimeofday(&(t->timeout));
    t->timeout = timeval_add(t->timeout, PASER_TB_HELLO_Interval);
    pGlobal->getTimer_queue()->timer_sort();
}

void PASER_route_maintenance::timeout_ROOT_TIMEOUT(PASER_timer_packet *t) {
    //send ROOT
    pGlobal->getPacketSender()->send_root();
    //remove timer
    pGlobal->getTimer_queue()->timer_remove(t);
    PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "Send ROOT.\n");
    delete t;
}

void PASER_route_maintenance::timeout_SSL_TIMEOUT(PASER_timer_packet *t) {
    //close Socket
    pGlobal->getPASER_socket()->closeSSLSocket(t->sslFD);
    //remove timer
    pGlobal->getTimer_queue()->timer_remove(t);
    delete t;
}

void PASER_route_maintenance::packetFailed(struct in_addr src, struct in_addr dest, bool sendRERR) {
    PASER_routing_entry *rEntry = pGlobal->getRouting_table()->findDest(dest);
    if (rEntry == NULL) {
        return;
    }
    PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(rEntry->nxthop_addr);
    if (nEntry == NULL) {
        return;
    }
    struct in_addr nextHop = nEntry->neighbor_addr;
    if (pGlobal->getRouting_table()->findDest(nextHop) == NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Root break to IP %s is detected.\n", inet_ntoa(src));
        return;
    }
    std::list<PASER_routing_entry*> EntryList = pGlobal->getRouting_table()->getListWithNextHop(nextHop);
    pGlobal->getRouting_table()->deleteFromKernelRoutingTableNodesWithNextHopAddr(nextHop);

    struct timeval now;
    pGlobal->getPASERtimeofday(&now);

//    if(sendRERR && pGlobal->getBlacklist()->setRerrTime(dest, now)){
    if (sendRERR) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Send RERR.\n");
        std::list<unreachableBlock> allAddrList;
//        allAddrList.push_front(nextHop);
        for (std::list<PASER_routing_entry*>::iterator it = EntryList.begin(); it != EntryList.end(); it++) {
            PASER_routing_entry *tempEntry = (PASER_routing_entry *) *it;
            unreachableBlock temp;
            temp.addr.s_addr = tempEntry->dest_addr.s_addr;
            temp.seq = tempEntry->seqnum;
            allAddrList.push_back(temp);
        }
        pGlobal->getPacketSender()->send_rerr(allAddrList);
    }
}
