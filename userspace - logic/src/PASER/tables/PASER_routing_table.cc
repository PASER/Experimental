/**
 *\class  		PASER_routing_table
 *@brief       	Class provides a map of node's routes.
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

#include "PASER_routing_table.h"

PASER_routing_table::PASER_routing_table(PASER_global *paser_global) {
    timer_queue = paser_global->getTimer_queue();
    neighbor_table = paser_global->getNeighbor_table();
    pGlobal = paser_global;

}

PASER_routing_table::~PASER_routing_table() {
    for (std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        PASER_routing_entry *temp = it->second;
        in_addr tempMask;
        tempMask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        pGlobal->getPASER_socket()->deleteRoute(temp->dest_addr, tempMask);
        for(std::list<address_range>::iterator it = temp->AddL.begin(); it != temp->AddL.end(); it++){
            address_range range = (address_range)*it;
            pGlobal->getPASER_socket()->deleteRoute(range.ipaddr, range.mask);
        }
        delete temp;
    }
    route_table.clear();
}

void PASER_routing_table::init() {

}

void PASER_routing_table::destroy() {

}

PASER_routing_entry *PASER_routing_table::findAdd(struct in_addr addr) {
    for (std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        PASER_routing_entry *tempEntry = it->second;
        for (std::list<address_range>::iterator it2 = tempEntry->AddL.begin(); it2 != tempEntry->AddL.end(); it2++) {
            address_range tempRange = (address_range) *it2;
            if ((tempRange.ipaddr.s_addr & tempRange.mask.s_addr) == (addr.s_addr & tempRange.mask.s_addr)) {
                return tempEntry;
            }
        }
    }
    return NULL;
}

/* Find an routing entry given the destination address */
PASER_routing_entry *PASER_routing_table::findDest(struct in_addr dest_addr) {
    if (dest_addr.s_addr == 0xFFFFFFFF) {
        return findBestGW();
    }
    std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.find(dest_addr.s_addr);
    if (it != route_table.end()) {
        if (it->second) {
            return it->second;
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "ERROR in Routing table structure!\n");
        }
    }
    return NULL;
}

PASER_routing_entry *PASER_routing_table::insert(struct in_addr dest_addr, struct in_addr nxthop_addr, PASER_timer_packet * deltimer,
        PASER_timer_packet * validtimer, u_int32_t seqnum, u_int8_t hopcnt, u_int8_t is_gw, std::list<address_range> AddL, u_int8_t *Cert) {
    PASER_routing_entry *entry = new PASER_routing_entry();
    entry->AddL.assign(AddL.begin(), AddL.end());
    entry->Cert = Cert;
    entry->deleteTimer = deltimer;
    entry->validTimer = validtimer;
    entry->dest_addr = dest_addr;
    entry->hopcnt = hopcnt;
    entry->is_gw = is_gw;
    entry->isValid = 1;
    entry->nxthop_addr = nxthop_addr;
    entry->seqnum = seqnum;

    route_table.insert(std::make_pair(dest_addr.s_addr, entry));
    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Insert route to routing table IP:%s", inet_ntoa(dest_addr));
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, " NextHop:%s , metric:%d\n", inet_ntoa(nxthop_addr), hopcnt);
    return entry;
}

PASER_routing_entry *PASER_routing_table::update(PASER_routing_entry *entry, struct in_addr dest_addr, struct in_addr nxthop_addr,
        PASER_timer_packet * deltimer, PASER_timer_packet * validtimer, u_int32_t seqnum, u_int8_t hopcnt, u_int8_t is_gw,
        std::list<address_range> AddL, u_int8_t *Cert) {
    u_int32_t oldSeq = entry->seqnum;
    u_int8_t *oldCert = NULL;
    if (entry) {
        std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.find(entry->dest_addr.s_addr);
        if (it != route_table.end()) {
            if ((*it).second == entry) {
                oldSeq = (*it).second->seqnum;
                route_table.erase(it);
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "ERROR in routing table structure!\n");
            }
        }
        if (entry->Cert && !Cert) {
            oldCert = entry->Cert;
            entry->Cert = NULL;
        }
        delete entry;
    }

    entry = new PASER_routing_entry();
    entry->AddL.assign(AddL.begin(), AddL.end());
    if (oldCert) {
        entry->Cert = oldCert;
    } else
        entry->Cert = Cert;
    entry->deleteTimer = deltimer;
    entry->validTimer = validtimer;
    entry->dest_addr = dest_addr;
    entry->hopcnt = hopcnt;
    entry->is_gw = is_gw;
    entry->nxthop_addr = nxthop_addr;
    entry->isValid = 1;
    if (seqnum != 0) {
        entry->seqnum = seqnum;
    } else {
        entry->seqnum = oldSeq;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Update route in routing table IP:%s", inet_ntoa(dest_addr));
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, " NextHop:%s , metric:%d\n", inet_ntoa(nxthop_addr), hopcnt);
    route_table.insert(std::make_pair(dest_addr.s_addr, entry));
    return entry;
}

void PASER_routing_table::delete_entry(PASER_routing_entry *entry) {
    if (!entry)
        return;

    std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.find(entry->dest_addr.s_addr);
    if (it != route_table.end()) {
        if ((*it).second == entry) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Delete route from routing table IP:%s\n", inet_ntoa(entry->dest_addr));
            route_table.erase(it);
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "ERROR in Routing table structure!\n");
        }
    }
}

PASER_routing_entry *PASER_routing_table::getRouteToGw() {
    return findBestGW();
}

PASER_routing_entry *PASER_routing_table::findBestGW() {
    // Pointer to best Route to GW
    PASER_routing_entry* tempBestRouteToGW = NULL;
    u_int32_t bestMetric = 0;
    for (std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        if ((*it).second->is_gw && (*it).second->isValid && (bestMetric == 0 || bestMetric > (*it).second->hopcnt)) {
            tempBestRouteToGW = (*it).second;
            bestMetric = tempBestRouteToGW->hopcnt;
        }
    }
    return tempBestRouteToGW;
}

std::list<PASER_routing_entry*> PASER_routing_table::getListWithNextHop(struct in_addr nextHop) {
    std::list<PASER_routing_entry*> returnList;
    for (std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        PASER_routing_entry *tempEntry = (*it).second;
        if (tempEntry->nxthop_addr.s_addr == nextHop.s_addr) {
            returnList.push_back(tempEntry);
        }
    }
    return returnList;
}

void PASER_routing_table::updateKernelRoutingTable(struct in_addr dest_addr, struct in_addr forw_addr, struct in_addr netmask,
        u_int32_t metric, bool del_entry, int ifIndex) {
#ifdef PASER_MODULE_TEST
    return;
#endif
    bool done = false;
    if (!del_entry) {
        //delete old entry
        pGlobal->getPASER_socket()->deleteRoute(dest_addr, netmask);
        //add new entry
        if (dest_addr.s_addr == forw_addr.s_addr) {
            network_device dev = DEV_NR(pGlobal->getPaser_configuration()->getIfIdFromIfIndex(ifIndex));
            done = pGlobal->getPASER_socket()->addRouteDev(dest_addr, netmask, &dev);
            //add statistics
            pGlobal->getPaserStatistic()->routingTableModificationAdd(dest_addr, dest_addr);
        } else {
            done = pGlobal->getPASER_socket()->addRouteVia(dest_addr, netmask, forw_addr);
            pGlobal->getPaserStatistic()->routingTableModificationAdd(dest_addr, forw_addr);
        }
        if (done) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Route to %s is added to kernel routing table\n", inet_ntoa(dest_addr));
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Route to %s is not added to kernel routing table\n", inet_ntoa(dest_addr));
        }
        //if necessary, update route to gateway
        PASER_routing_entry *rEntry = findDest(dest_addr);
        if (rEntry && rEntry->is_gw) {
            PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
            if (nEntry && nEntry->isValid && nEntry->neighFlag && pGlobal->getRouting_table()->getRouteToGw() == rEntry) {
                network_device dev = DEV_NR(pGlobal->getPaser_configuration()->getIfIdFromIfIndex(nEntry->ifIndex));
                pGlobal->getPASER_socket()->deleteDefaultRoute();
                pGlobal->getPASER_socket()->addDefaultRoute(nEntry->neighbor_addr, &dev, rEntry->hopcnt);
                pGlobal->getPASER_socket()->setGWFlag(true);
            }
        }
    }
    else {
        done = pGlobal->getPASER_socket()->deleteRoute(dest_addr, netmask);
        //add statistic
        pGlobal->getPaserStatistic()->routingTableModificationDelete(dest_addr);
        if(pGlobal->getRouting_table()->getRouteToGw() == NULL) {
            pGlobal->getPASER_socket()->setGWFlag(false);
        }
        if(done) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Route to %s is deleted from kernel routing table\n", inet_ntoa(dest_addr));
        }
        else {
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Route to %s is not deleted from kernel routing table\n", inet_ntoa(dest_addr));
        }
    }
}

void PASER_routing_table::updateRoutingTableAndSetTableTimeout(std::list<address_range> addList, struct in_addr src_addr, uint32_t seq,
        X509 *cert, struct in_addr nextHop, u_int8_t metric, int ifIndex, struct timeval now, u_int8_t gFlag, bool trusted) {
    PASER_routing_entry *entry = findDest(src_addr);

    PASER_timer_packet *deletePack = NULL;
    PASER_timer_packet *validPack = NULL;
    if (entry) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Update timeout in routing table for IP:%s\n", inet_ntoa(src_addr));
        deletePack = entry->deleteTimer;
        validPack = entry->validTimer;
        if (validPack == NULL) {
            validPack = new PASER_timer_packet();
            validPack->data = NULL;
            validPack->destAddr.s_addr = src_addr.s_addr;
            validPack->handler = ROUTINGTABLE_VALID_ENTRY;
            entry->validTimer = validPack;
        }
    } else {
        deletePack = new PASER_timer_packet();
        deletePack->data = NULL;
        deletePack->destAddr.s_addr = src_addr.s_addr;
        deletePack->handler = ROUTINGTABLE_DELETE_ENTRY;
        validPack = new PASER_timer_packet();
        validPack->data = NULL;
        validPack->destAddr.s_addr = src_addr.s_addr;
        validPack->handler = ROUTINGTABLE_VALID_ENTRY;
    }
    deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
    validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

    timer_queue->timer_add(deletePack);
    timer_queue->timer_add(validPack);

    if (entry != NULL) {
        PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(entry->nxthop_addr);
        if (nEntry && nEntry->neighFlag) {
//            if(entry->hopcnt <= (metric + 1) && entry->isValid && seq!=0 && seq<=entry->seqnum){
//            if(entry->hopcnt <= (metric + 1) && entry->isValid && seq!=0 && (paser_global->isSeqNew(seq, entry->seqnum) || seq == entry->seqnum)){
            if (entry->hopcnt <= (metric + 1) && entry->isValid && seq != 0 && !pGlobal->isSeqNew(entry->seqnum, seq)) {
                if (seq != 0) {
                    entry->seqnum = seq;
                }
                if (entry->Cert && cert) {
                    X509_free((X509*) entry->Cert);
                    entry->Cert = (u_int8_t*) cert;
                } else if (!entry->Cert && cert) {
                    entry->Cert = (u_int8_t*) cert;
                }

                struct in_addr netmask;
                netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
                updateKernelRoutingTable(entry->dest_addr, entry->nxthop_addr, netmask, entry->hopcnt, false, nEntry->ifIndex);
                return;
            } else {
                nEntry = neighbor_table->findNeigh(nextHop);
                struct in_addr netmask;
                netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
//                updateKernelRoutingTable(entry->dest_addr, entry->nxthop_addr, netmask, metric + 1, true, nEntry->ifIndex);
                updateKernelRoutingTable(src_addr, nextHop, netmask, metric + 1, false, nEntry->ifIndex);

                update(entry, src_addr, nextHop, deletePack, validPack, seq, metric + 1, entry->is_gw | gFlag, addList, (u_int8_t*) cert);
                return;
            }
        }

        if (nEntry && entry->seqnum == seq) {
            if (cert) {
                X509_free((X509*) cert);
            }
            return;
        }
        update(entry, src_addr, nextHop, deletePack, validPack, seq, metric + 1, entry->is_gw | gFlag, addList, (u_int8_t*) cert);

        struct in_addr netmask;
        netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
//        updateKernelRoutingTable(src_addr, nextHop, netmask, metric + 1, true, ifIndex);
        updateKernelRoutingTable(src_addr, nextHop, netmask, metric + 1, false, ifIndex);
    } else {
        insert(src_addr, nextHop, deletePack, validPack, seq, metric + 1, gFlag, addList, (u_int8_t*) cert);

        struct in_addr netmask;
        netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        PASER_neighbor_entry *tempEntry = neighbor_table->findNeigh(nextHop);
        if (tempEntry) {
            updateKernelRoutingTable(src_addr, nextHop, netmask, metric + 1, false, tempEntry->ifIndex);
        } else {
            updateKernelRoutingTable(src_addr, nextHop, netmask, metric + 1, false, ifIndex);
        }
    }
    return;
}

void PASER_routing_table::updateRoutingTableTimeout(struct in_addr src_addr, struct timeval now, int ifIndex) {
    PASER_routing_entry *entry = findDest(src_addr);
    if (!entry) {
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Update timeout in routing table for IP:%s", inet_ntoa(src_addr));
    PASER_timer_packet *deletePack = entry->deleteTimer;
    PASER_timer_packet *validPack = entry->validTimer;
    if (validPack == NULL) {
        validPack = new PASER_timer_packet();
        validPack->data = NULL;
        validPack->destAddr.s_addr = src_addr.s_addr;
        validPack->handler = ROUTINGTABLE_VALID_ENTRY;
        entry->validTimer = validPack;
    }
    entry->isValid = 1;
    deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
    validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);
    timer_queue->timer_add(deletePack);
    timer_queue->timer_add(validPack);

    struct in_addr netmask;
    netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
//    updateKernelRoutingTable(src_addr, src_addr, netmask, 1, true, ifIndex);
    updateKernelRoutingTable(src_addr, src_addr, netmask, 1, false, ifIndex);
}

void PASER_routing_table::updateRoutingTableTimeout(struct in_addr src_addr, u_int32_t seq, struct timeval now) {
    PASER_routing_entry *entry = findDest(src_addr);
    if (!entry) {
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Update timeout in routing table for IP:%s\n", inet_ntoa(src_addr));
    PASER_timer_packet *deletePack = entry->deleteTimer;
    PASER_timer_packet *validPack = entry->validTimer;
    if (validPack == NULL) {
        validPack = new PASER_timer_packet();
        validPack->data = NULL;
        validPack->destAddr.s_addr = src_addr.s_addr;
        validPack->handler = ROUTINGTABLE_VALID_ENTRY;
        entry->validTimer = validPack;
    }
    deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
    validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);
    timer_queue->timer_add(deletePack);
    timer_queue->timer_add(validPack);

    entry->seqnum = seq;
    entry->isValid = 1;
}

void PASER_routing_table::updateRoutingTable(struct timeval now, std::list<address_list> addList, struct in_addr nextHop, int ifIndex) {
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nextHop);
    if (!nEntry || !nEntry->neighFlag || !nEntry->isValid) {
        return;
    }

    int hopCount = addList.size() + 1;
    for (std::list<address_list>::iterator it = addList.begin(); it != addList.end(); it++) {
        hopCount--;
        address_list tempList = (address_list) *it;
        PASER_routing_entry *rEntry = findDest(tempList.ipaddr);
        if (rEntry && rEntry->hopcnt <= hopCount) {
            for (std::list<address_range>::iterator it2 = tempList.range.begin(); it2 != tempList.range.end(); it2++) {

                address_range tempRange = (address_range) *it2;
                updateKernelRoutingTable(tempRange.ipaddr, nextHop, tempRange.mask, hopCount + 1, false, ifIndex);
            }
            continue;
        }
        if (!rEntry) {
            PASER_timer_packet *deletePack = NULL;
            PASER_timer_packet *validPack = NULL;
            deletePack = new PASER_timer_packet();
            deletePack->data = NULL;
            deletePack->destAddr.s_addr = tempList.ipaddr.s_addr;
            deletePack->handler = ROUTINGTABLE_DELETE_ENTRY;
            validPack = new PASER_timer_packet();
            validPack->data = NULL;
            validPack->destAddr.s_addr = tempList.ipaddr.s_addr;
            validPack->handler = ROUTINGTABLE_VALID_ENTRY;
            deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
            validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

            timer_queue->timer_add(deletePack);
            timer_queue->timer_add(validPack);
            insert(tempList.ipaddr, nextHop, deletePack, validPack, 0, hopCount, 0, tempList.range, NULL);
        } else {
            PASER_timer_packet *deletePack = NULL;
            PASER_timer_packet *validPack = NULL;
            deletePack = rEntry->deleteTimer;
            validPack = rEntry->validTimer;
            if (validPack == NULL) {
                validPack = new PASER_timer_packet();
                validPack->data = NULL;
                validPack->destAddr.s_addr = tempList.ipaddr.s_addr;
                validPack->handler = ROUTINGTABLE_VALID_ENTRY;
                rEntry->validTimer = validPack;
            }
            deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
            validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

            timer_queue->timer_add(deletePack);
            timer_queue->timer_add(validPack);
            update(rEntry, tempList.ipaddr, nextHop, deletePack, validPack, rEntry->seqnum, hopCount, rEntry->is_gw, tempList.range, NULL);
        }

        struct in_addr netmask;
        netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        updateKernelRoutingTable(tempList.ipaddr, nextHop, netmask, hopCount, false, ifIndex);

        for (std::list<address_range>::iterator it2 = tempList.range.begin(); it2 != tempList.range.end(); it2++) {
            address_range tempRange = (address_range) *it2;
            updateKernelRoutingTable(tempRange.ipaddr, nextHop, tempRange.mask, hopCount + 1, false, ifIndex);
        }
    }
}

void PASER_routing_table::deleteFromKernelRoutingTableNodesWithNextHopAddr(struct in_addr nextHop) {
    std::list<PASER_routing_entry*> EntryList = getListWithNextHop(nextHop);
    for (std::list<PASER_routing_entry*>::iterator it = EntryList.begin(); it != EntryList.end(); it++) {
        PASER_routing_entry *tempEntry = (PASER_routing_entry *) *it;
        for (std::list<address_range>::iterator it2 = tempEntry->AddL.begin(); it2 != tempEntry->AddL.end(); it2++) {

            address_range addList = (address_range) *it2;
            updateKernelRoutingTable(addList.ipaddr, nextHop, addList.mask, tempEntry->hopcnt + 1, true, 1);
        }

        in_addr tempMask;
        tempMask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        updateKernelRoutingTable(tempEntry->dest_addr, tempEntry->nxthop_addr, tempMask, tempEntry->hopcnt, true, 1);
        PASER_timer_packet *validTimer = tempEntry->validTimer;
        if (validTimer) {
            timer_queue->timer_remove(validTimer);
            delete validTimer;
            tempEntry->validTimer = NULL;
        }
        tempEntry->isValid = 0;
    }

    PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(nextHop);
    if (nEntry) {
        nEntry->isValid = 0;
        PASER_timer_packet *validTimer = nEntry->validTimer;
        if (validTimer) {
            timer_queue->timer_remove(validTimer);
            delete validTimer;
            nEntry->validTimer = NULL;
        }
    }

    PASER_routing_entry *rEntry = findDest(nextHop);
    if (!rEntry) {
        return;
    }
    for (std::list<address_range>::iterator it2 = rEntry->AddL.begin(); it2 != rEntry->AddL.end(); it2++) {

        address_range addList = (address_range) *it2;
        updateKernelRoutingTable(addList.ipaddr, nextHop, addList.mask, rEntry->hopcnt + 1, true, 1);
    }
    in_addr tempMask;
    tempMask.s_addr = PASER_ALLONES_ADDRESS_MASK;
    updateKernelRoutingTable(rEntry->dest_addr, rEntry->nxthop_addr, tempMask, rEntry->hopcnt, true, 1);
    PASER_timer_packet *validTimer = rEntry->validTimer;
    if (validTimer) {
        timer_queue->timer_remove(validTimer);
        delete validTimer;
        rEntry->validTimer = NULL;
    }
    rEntry->isValid = 0;
}

void PASER_routing_table::updateRouteLifetimes(struct in_addr dest_addr) {
    // update Timer for Source Node
    PASER_routing_entry *rEntry = findDest(dest_addr);
    if (!rEntry) {
        rEntry = findAdd(dest_addr);
        if (!rEntry) {
            return;
        }
    }
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    PASER_timer_packet *deletePack = rEntry->deleteTimer;
    PASER_timer_packet *validPack = rEntry->validTimer;
    if (rEntry->isValid == 0 || validPack == NULL) {
        return;
    }
//    rEntry->isValid = 1;
//    if (validPack == NULL) {
//        validPack = new PASER_timer_packet();
//        validPack->data = NULL;
//        validPack->destAddr.s_addr = dest_addr.s_addr;
//        validPack->handler = ROUTINGTABLE_VALID_ENTRY;
//        rEntry->validTimer = validPack;
//    }
    deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
    validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

    timer_queue->timer_add(deletePack);
    timer_queue->timer_add(validPack);

    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Update timeout in routing table for IP:%s", inet_ntoa(dest_addr));
    //Information ueber den NextHop wird aktualisiert nur wenn keine HELLO Nachrichten versendet werden
    if (true) {
        return;
    }
//    if (paser_global->isHelloActive()) {
//        return;
//    }

// update Timer for Forwarding Node in Neighbor Table
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
    if (!nEntry || nEntry->isValid == 0) {
        return;
    }
    PASER_timer_packet *NdeletePack = nEntry->deleteTimer;
    PASER_timer_packet *NvalidPack = nEntry->validTimer;
    if (NvalidPack == NULL) {
        PASER_timer_packet* tempValidTime = new PASER_timer_packet();
        tempValidTime->data = NULL;
        tempValidTime->destAddr.s_addr = nEntry->neighbor_addr.s_addr;
        tempValidTime->handler = NEIGHBORTABLE_VALID_ENTRY;
        nEntry->setValidTimer(tempValidTime);
        NvalidPack = tempValidTime;
    }
    nEntry->isValid = 1;
    NdeletePack->timeout = timeval_add(now, PASER_NEIGHBOR_DELETE_TIME);
    NvalidPack->timeout = timeval_add(now, PASER_NEIGHBOR_VALID_TIME);

    timer_queue->timer_add(NdeletePack);
    timer_queue->timer_add(NvalidPack);

    // update Timer for Forwarding Node in Routing Table
    PASER_routing_entry *rNeighborEntry = findDest(rEntry->nxthop_addr);
    if (!rNeighborEntry || rNeighborEntry->isValid == 0) {
        return;
    }
    PASER_timer_packet *deleteRoutingPack = rNeighborEntry->deleteTimer;
    PASER_timer_packet *validRoutingPack = rNeighborEntry->validTimer;
    if (validRoutingPack == NULL) {
        validRoutingPack = new PASER_timer_packet();
        validRoutingPack->data = NULL;
        validRoutingPack->destAddr.s_addr = rNeighborEntry->nxthop_addr.s_addr;
        validRoutingPack->handler = ROUTINGTABLE_VALID_ENTRY;
        rNeighborEntry->validTimer = validRoutingPack;
    }
    rNeighborEntry->isValid = 1;
    deleteRoutingPack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
    validRoutingPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

    timer_queue->timer_add(deleteRoutingPack);
    timer_queue->timer_add(validRoutingPack);
}

std::list<address_list> PASER_routing_table::getNeighborAddressList(int ifNr) {
    std::list<address_list> liste;
    for (std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        PASER_routing_entry *rEntry = it->second;
        PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
        if (rEntry->hopcnt == 1 && nEntry != NULL && nEntry->neighFlag && nEntry->isValid) {
            address_list temp;
            temp.ipaddr.s_addr = nEntry->neighbor_addr.s_addr;
            for (std::list<address_range>::iterator inIt = rEntry->AddL.begin(); inIt != rEntry->AddL.end(); inIt++) {
                temp.range.push_back((address_range) *inIt);
            }
            liste.push_back(temp);
        }
    }
    in_addr WlanAddrStruct;
    network_device *tempDevice = pGlobal->getPaser_configuration()->getNetDevice();
    WlanAddrStruct.s_addr = tempDevice[ifNr].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    liste.push_back(myAddrList);
    return liste;
}

void PASER_routing_table::updateNeighborFromHELLO(address_list liste, u_int32_t seq, int ifIndex) {
    PASER_routing_entry *rEntry = findDest(liste.ipaddr);
    if (rEntry == NULL) {
        return;
    }
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
    if (nEntry == NULL || !nEntry->neighFlag) {
        return;
    }
    //get Time
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);

    //update RouteTimeout
    PASER_timer_packet *deletePack = NULL;
    PASER_timer_packet *validPack = NULL;
    deletePack = rEntry->deleteTimer;
    validPack = rEntry->validTimer;
    if (validPack == NULL) {
        validPack = new PASER_timer_packet();
        validPack->data = NULL;
        validPack->destAddr.s_addr = liste.ipaddr.s_addr;
        validPack->handler = ROUTINGTABLE_VALID_ENTRY;
        rEntry->validTimer = validPack;
    }
    deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
    validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

    timer_queue->timer_add(deletePack);
    timer_queue->timer_add(validPack);
    rEntry = update(rEntry, liste.ipaddr, rEntry->nxthop_addr, deletePack, validPack, rEntry->seqnum, 1, rEntry->is_gw, liste.range, NULL);

    struct in_addr netmask;
    netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
    updateKernelRoutingTable(liste.ipaddr, rEntry->nxthop_addr, netmask, 1, false, ifIndex);

//update NeighborTimeout
    neighbor_table->updateNeighborTableTimeout(rEntry->nxthop_addr, now);

//update AddList
    for (std::list<address_range>::iterator it2 = liste.range.begin(); it2 != liste.range.end(); it2++) {

        address_range tempRange = (address_range) *it2;
        updateKernelRoutingTable(tempRange.ipaddr, rEntry->nxthop_addr, tempRange.mask, 2, false, ifIndex);
    }

}

void PASER_routing_table::updateRouteFromHELLO(address_list liste, int ifIndex, struct in_addr nextHop) {
    PASER_routing_entry *rEntry = findDest(liste.ipaddr);
    if (rEntry && rEntry->hopcnt == 1 && rEntry->isValid && rEntry->nxthop_addr.s_addr != nextHop.s_addr) {
        PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
        if (nEntry && nEntry->isValid && nEntry->neighFlag) {
            // The route to the node over the neighbor is worst that knowing route
            return;
        }
    }
    if (rEntry && rEntry->hopcnt == 2 && rEntry->isValid && rEntry->nxthop_addr.s_addr != nextHop.s_addr) {
        PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
        if (nEntry && nEntry->isValid && nEntry->neighFlag) {
            // An alternative route is known, which is just as well.
            return;
        }
    }
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    if (!rEntry) {
        PASER_timer_packet *deletePack = NULL;
        PASER_timer_packet *validPack = NULL;
        deletePack = new PASER_timer_packet();
        deletePack->data = NULL;
        deletePack->destAddr.s_addr = liste.ipaddr.s_addr;
        deletePack->handler = ROUTINGTABLE_DELETE_ENTRY;
        validPack = new PASER_timer_packet();
        validPack->data = NULL;
        validPack->destAddr.s_addr = liste.ipaddr.s_addr;
        validPack->handler = ROUTINGTABLE_VALID_ENTRY;
        deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
        validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

        timer_queue->timer_add(deletePack);
        timer_queue->timer_add(validPack);
        insert(liste.ipaddr, nextHop, deletePack, validPack, 0, 2, 0, liste.range, NULL);
    } else {
        PASER_timer_packet *deletePack = NULL;
        PASER_timer_packet *validPack = NULL;
        deletePack = rEntry->deleteTimer;
        validPack = rEntry->validTimer;
        if (validPack == NULL) {
            validPack = new PASER_timer_packet();
            validPack->data = NULL;
            validPack->destAddr.s_addr = liste.ipaddr.s_addr;
            validPack->handler = ROUTINGTABLE_VALID_ENTRY;
            rEntry->validTimer = validPack;
        }
        deletePack->timeout = timeval_add(now, PASER_ROUTE_DELETE_TIME);
        validPack->timeout = timeval_add(now, PASER_ROUTE_VALID_TIME);

        timer_queue->timer_add(deletePack);
        timer_queue->timer_add(validPack);
        update(rEntry, liste.ipaddr, nextHop, deletePack, validPack, rEntry->seqnum, 2, rEntry->is_gw, liste.range, NULL);
    }

    struct in_addr netmask;
    netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
    updateKernelRoutingTable(liste.ipaddr, nextHop, netmask, 2, false, ifIndex);

    for (std::list<address_range>::iterator it2 = liste.range.begin(); it2 != liste.range.end(); it2++) {

        address_range tempRange = (address_range) *it2;
        updateKernelRoutingTable(liste.ipaddr, nextHop, tempRange.mask, 3, false, ifIndex);
    }
}

std::string PASER_routing_table::shortInfo() {
    std::stringstream out;
    int i = 1;
    out << "Routing table:\n";
    for (std::map<Uint128, PASER_routing_entry *>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        PASER_routing_entry *rEntry = it->second;
        out << " Routing Entry " << i;
        out << ": Dest IP: " << inet_ntoa(rEntry->dest_addr);
        out << ": NextHop IP: " << inet_ntoa(rEntry->nxthop_addr);
        out << " Is Valid: " << (int) rEntry->isValid;
        out << " Metric: " << (int) rEntry->hopcnt;
        if (rEntry->isValid) {
            out << " vTimer: " << rEntry->validTimer->timeout.tv_sec;
        }
        out << "\n";
        i++;
    }
    return out.str();
}

std::string PASER_routing_table::detailedInfo() {
    std::stringstream out;
    int i = 1;
    out << "Routing table:\n";
    for (std::map<Uint128, PASER_routing_entry *>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        PASER_routing_entry *rEntry = it->second;
        out << " Routing Entry " << i << "\n";
        out << rEntry->detailedInfo();
        i++;
    }
    return out.str();
}

void PASER_routing_table::clearTable() {
    //reset RoutinigTable
    for (std::map<Uint128, PASER_routing_entry*>::iterator it = route_table.begin(); it != route_table.end(); it++) {
        PASER_routing_entry *temp = it->second;
        // delete Route from kernel routing table
        pGlobal->getPASER_socket()->deleteRoute(temp->dest_addr, temp->dest_addr);
        for (std::list<address_range>::iterator it2 = temp->AddL.begin(); it2 != temp->AddL.end(); it2++) {
            address_range tempRange = (address_range) *it2;
            pGlobal->getPASER_socket()->deleteRoute(tempRange.ipaddr, tempRange.mask);
        }
        delete temp;
    }
    route_table.clear();
}
