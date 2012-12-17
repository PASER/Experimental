/**
 *\class  		PASER_neighbor_table
 *@brief       	Class provides a map of node's neighbors.
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

#include "PASER_neighbor_table.h"
#include "../crypto/PASER_crypto_sign.h"

PASER_neighbor_table::PASER_neighbor_table(PASER_global *paser_global) {
    pGlobal = paser_global;
    timer_queue = paser_global->getTimer_queue();
}

PASER_neighbor_table::~PASER_neighbor_table() {
    for (std::map<Uint128, PASER_neighbor_entry*>::iterator it = neighbor_table_map.begin(); it != neighbor_table_map.end(); it++) {
        PASER_neighbor_entry *temp = it->second;
        delete temp;
    }
    neighbor_table_map.clear();
}

/* Find an neighbor entry given the destination address */
PASER_neighbor_entry *PASER_neighbor_table::findNeigh(struct in_addr neigh_addr) {
    std::map<Uint128, PASER_neighbor_entry*>::iterator it = neighbor_table_map.find(neigh_addr.s_addr);
    if (it != neighbor_table_map.end()) {
        if (it->second)
            return it->second;
    }
    return NULL;
}

PASER_neighbor_entry *PASER_neighbor_table::insert(struct in_addr neigh_addr, PASER_timer_packet * deleteTimer,
        PASER_timer_packet * validTimer, int neighFlag, u_int8_t *root, u_int32_t IV, geo_pos position, u_int8_t *Cert, u_int32_t ifIndex) {
    PASER_neighbor_entry *entry = new PASER_neighbor_entry();
    entry->IV = IV;
    entry->neighFlag = neighFlag;
    entry->neighbor_addr.s_addr = neigh_addr.s_addr;
    entry->deleteTimer = deleteTimer;
    entry->validTimer = validTimer;
    entry->position.lat = position.lat;
    entry->position.lon = position.lon;
    entry->Cert = Cert;
    entry->root = root;
    entry->isValid = 1;
    entry->ifIndex = ifIndex;

    neighbor_table_map.insert(std::make_pair(neigh_addr.s_addr, entry));
    return entry;
}

PASER_neighbor_entry *PASER_neighbor_table::update(PASER_neighbor_entry *entry, struct in_addr neigh_addr, PASER_timer_packet * deleteTimer,
        PASER_timer_packet * validTimer, int neighFlag, u_int8_t *root, u_int32_t IV, geo_pos position, u_int8_t *Cert, u_int32_t ifIndex) {
    if (entry) {
        std::map<Uint128, PASER_neighbor_entry*>::iterator it = neighbor_table_map.find(entry->neighbor_addr.s_addr);
        if (it != neighbor_table_map.end()) {
            if ((*it).second == entry) {
                neighbor_table_map.erase(it);
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "ERROR in Neighbor table structure!\n");
            }
        }
        delete entry;
    }

    entry = new PASER_neighbor_entry();
    entry->IV = IV;
    entry->neighFlag = neighFlag;
    entry->neighbor_addr.s_addr = neigh_addr.s_addr;
    entry->deleteTimer = deleteTimer;
    entry->validTimer = validTimer;
    entry->position.lat = position.lat;
    entry->position.lon = position.lon;
    entry->Cert = Cert;
    entry->root = root;
    entry->isValid = 1;
    entry->ifIndex = ifIndex;

    neighbor_table_map.insert(std::make_pair(neigh_addr.s_addr, entry));
    return entry;
}

void PASER_neighbor_table::delete_entry(PASER_neighbor_entry *entry) {
    if (!entry)
        return;

    if (entry) {
        std::map<Uint128, PASER_neighbor_entry*>::iterator it = neighbor_table_map.find(entry->neighbor_addr.s_addr);
        if (it != neighbor_table_map.end()) {
            if ((*it).second == entry) {
                neighbor_table_map.erase(it);
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "ERROR in Neighbor table structure!\n");
            }
        }
    }
}

void PASER_neighbor_table::updateNeighborTableAndSetTableTimeout(struct in_addr neigh, int nFlag, u_int8_t *root, int iv, geo_pos position,
        X509 *cert, struct timeval now, u_int32_t ifIndex)
{
    PASER_timer_packet *deletePack = NULL;
    PASER_timer_packet *validPack = NULL;
    PASER_neighbor_entry *nEntry = findNeigh(neigh);
    int32_t setTrusted = 0;
    if (nEntry)
    {
        setTrusted = nEntry->neighFlag;
        deletePack = nEntry->deleteTimer;
        validPack = nEntry->validTimer;
        if (validPack == NULL)
        {
            validPack = new PASER_timer_packet();
            validPack->data = NULL;
            validPack->destAddr.s_addr = neigh.s_addr;
            validPack->handler = NEIGHBORTABLE_VALID_ENTRY;
            nEntry->validTimer = validPack;
            validPack->timeout = timeval_add(now, PASER_NEIGHBOR_VALID_TIME);
            setTrusted = 0;
        }
        else
        {
            validPack->timeout = timeval_add(now, PASER_NEIGHBOR_VALID_TIME);
        }
        deletePack->timeout = timeval_add(now, PASER_NEIGHBOR_DELETE_TIME);
    }
    else
    {
        setTrusted = nFlag;
        deletePack = new PASER_timer_packet();
        deletePack->data = NULL;
        deletePack->destAddr.s_addr = neigh.s_addr;
        deletePack->handler = NEIGHBORTABLE_DELETE_ENTRY;
        validPack = new PASER_timer_packet();
        validPack->data = NULL;
        validPack->destAddr.s_addr = neigh.s_addr;
        validPack->handler = NEIGHBORTABLE_VALID_ENTRY;
        deletePack->timeout = timeval_add(now, PASER_NEIGHBOR_DELETE_TIME);
        validPack->timeout = timeval_add(now, PASER_NEIGHBOR_VALID_TIME);
    }

    if (validPack != NULL)
    {
        timer_queue->timer_add(validPack);
    }
    timer_queue->timer_add(deletePack);

    u_int8_t *rootN = (u_int8_t *) malloc((sizeof(u_int8_t) * SHA256_DIGEST_LENGTH));
    memcpy(rootN, root, (sizeof(u_int8_t) * SHA256_DIGEST_LENGTH));
    if (nEntry == NULL)
    {
        nEntry = insert(neigh, deletePack, validPack, nFlag, rootN, iv, position, (u_int8_t*) cert, ifIndex);
    }
    else
    {
        int tempFlag = 0;
        if (nEntry->neighFlag || nFlag)
        {
            tempFlag = 1;
        }
        nEntry = update(nEntry, neigh, deletePack, validPack, tempFlag, rootN, iv, position, (u_int8_t*) cert, ifIndex);
    }
    nEntry->neighFlag = setTrusted || nFlag;
}

void PASER_neighbor_table::updateNeighborTableTimeout(struct in_addr neigh, struct timeval now) {
    PASER_timer_packet *deletePack = NULL;
    PASER_timer_packet *validPack = NULL;
    PASER_neighbor_entry *nEntry = findNeigh(neigh);
    if (nEntry) {
        deletePack = nEntry->deleteTimer;
        validPack = nEntry->validTimer;
        if (validPack == NULL) {
            validPack = new PASER_timer_packet();
            validPack->data = NULL;
            validPack->destAddr.s_addr = neigh.s_addr;
            validPack->handler = NEIGHBORTABLE_VALID_ENTRY;
            nEntry->validTimer = validPack;
        }
    } else {
        return;
    }
    nEntry->isValid = 1;
    deletePack->timeout = timeval_add(now, PASER_NEIGHBOR_DELETE_TIME);
    validPack->timeout = timeval_add(now, PASER_NEIGHBOR_VALID_TIME);

    timer_queue->timer_add(deletePack);
    timer_queue->timer_add(validPack);
}

void PASER_neighbor_table::updateNeighborTableIVandSetValid(struct in_addr neigh, u_int32_t IV) {
    PASER_neighbor_entry *nEntry = findNeigh(neigh);
    if (nEntry) {
        nEntry->IV = IV;
        nEntry->isValid = 1;
    } else {
        return;
    }
}

void PASER_neighbor_table::updateNeighborTableIV(struct in_addr neigh, u_int32_t IV) {
    PASER_neighbor_entry *nEntry = findNeigh(neigh);
    if (nEntry) {
        nEntry->IV = IV;
    } else {
        return;
    }
}

int PASER_neighbor_table::checkAllCert() {
    int i = 0;
    bool found = true;
    while (found) {
        found = false;
        int j = 0;
        for (std::map<Uint128, PASER_neighbor_entry *>::iterator it = neighbor_table_map.begin(); it != neighbor_table_map.end(); it++) {
            if (j >= i) {
                PASER_neighbor_entry *nEntry = it->second;
                if (pGlobal->getCrypto_sign()->checkOneCert((X509*) nEntry->Cert) == 0) {
                    found = true;
                    //delete neighbor
                    delete_entry(nEntry);
                    if (nEntry->deleteTimer) {
                        timer_queue->timer_remove(nEntry->deleteTimer);
                        delete nEntry->deleteTimer;
                    }
                    if (nEntry->validTimer) {
                        timer_queue->timer_remove(nEntry->validTimer);
                        delete nEntry->validTimer;
                    }
                    //delete all routes
                    std::list<PASER_routing_entry*> routeList = pGlobal->getRouting_table()->getListWithNextHop(nEntry->neighbor_addr);
                    for (std::list<PASER_routing_entry*>::iterator it2 = routeList.begin(); it2 != routeList.end(); it2++) {
                        PASER_routing_entry *tempEntry = (PASER_routing_entry*) *it2;
                        if (tempEntry) {
                            pGlobal->getRouting_table()->delete_entry(tempEntry);
                            if (tempEntry->deleteTimer) {
                                timer_queue->timer_remove(tempEntry->deleteTimer);
                                delete tempEntry->deleteTimer;
                            }
                            if (tempEntry->validTimer) {
                                timer_queue->timer_remove(tempEntry->validTimer);
                                delete tempEntry->validTimer;
                            }
                            delete tempEntry;
                        }
                    }
                    delete nEntry;
                    break;
                }
            }
            i++;
            j++;
        }
    }
//    PASER_routing_entry *routeToGW = pGlobal->getRouting_table()->getRouteToGw();
//    if(routeToGW){
//        return 1;
//    }
    return 0;
}

std::string PASER_neighbor_table::shortInfo() {
    std::stringstream out;
    int i = 1;
    out << "Neighbor Table: \n";
    for (std::map<Uint128, PASER_neighbor_entry *>::iterator it = neighbor_table_map.begin(); it != neighbor_table_map.end(); it++) {
        PASER_neighbor_entry *nEntry = it->second;
        out << " Neighbor Entry " << i;
        out << ": IP: " << inet_ntoa(nEntry->neighbor_addr);
        out << " Flag: " << nEntry->neighFlag << "";
        out << " Is Valid: " << (int) nEntry->isValid;
        if (nEntry->isValid) {
            out << " vTimer: " << nEntry->validTimer->timeout.tv_sec;
        }
        out << "\n";
        i++;
    }
    return out.str();
}

std::string PASER_neighbor_table::detailedInfo() {
    std::stringstream out;
    int i = 1;
    out << "Neighbor Table: \n";
    for (std::map<Uint128, PASER_neighbor_entry *>::iterator it = neighbor_table_map.begin(); it != neighbor_table_map.end(); it++) {
        PASER_neighbor_entry *nEntry = it->second;
        out << " Neighbor Entry " << i << "\n";
        out << nEntry->detailedInfo();
        i++;
    }
    return out.str();
}

void PASER_neighbor_table::clearTable() {
    for (std::map<Uint128, PASER_neighbor_entry*>::iterator it = neighbor_table_map.begin(); it != neighbor_table_map.end(); it++) {
        PASER_neighbor_entry *temp = it->second;
        delete temp;
    }
    neighbor_table_map.clear();
}
