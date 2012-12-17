/**
 *\class  		PASER_rreq_list
 *@brief       	Class represents an entry in the RREQ list
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

#include "PASER_rreq_list.h"
#include "../config/PASER_defs.h"

PASER_rreq_list::~PASER_rreq_list(){
    for (std::map<Uint128, packet_rreq_entry * >::iterator it = rreq_list.begin(); it!=rreq_list.end(); it++){
        packet_rreq_entry *temp = it->second;
        delete temp;
    }
    rreq_list.clear();
}

packet_rreq_entry* PASER_rreq_list::pending_add(struct in_addr dest_addr){
    packet_rreq_entry *entry = pending_find(dest_addr);
    if (entry)
          return entry;
    entry = new packet_rreq_entry();

    if (entry== NULL)
    {
        exit(EXIT_FAILURE);
    }

    entry->dest_addr.s_addr = dest_addr.s_addr;
    entry->tries        = 0;
    rreq_list.insert(std::make_pair(dest_addr.s_addr,entry));
    return entry;
}

int PASER_rreq_list::pending_remove(packet_rreq_entry *entry){
    if (!entry)
        return 0;

    std::map<Uint128, packet_rreq_entry * >::iterator it = rreq_list.find(entry->dest_addr.s_addr);
    if (it != rreq_list.end())
    {
        if ((*it).second == entry)
        {
            rreq_list.erase(it);
        }
        else{

        }

    }
    return 1;
}

packet_rreq_entry* PASER_rreq_list::pending_find(struct in_addr dest_addr){
    std::map<Uint128, packet_rreq_entry * >::iterator it = rreq_list.find(dest_addr.s_addr);
    if (it != rreq_list.end())
    {
        packet_rreq_entry *entry = it->second;
        if (entry->dest_addr.s_addr == dest_addr.s_addr)
            return entry;
        else{

        }
    }
    return NULL;
}

packet_rreq_entry* PASER_rreq_list::pending_find_addr_with_mask(struct in_addr dest_addr, struct in_addr dest_mask){
    for(std::map<Uint128, packet_rreq_entry * >::iterator it = rreq_list.begin(); it!=rreq_list.end(); it++){
        Uint128 tempAddr = it->first;
        packet_rreq_entry *entry = it->second;
        if( (tempAddr & dest_mask.s_addr) == (dest_addr.s_addr & dest_mask.s_addr) ){
            return entry;
        }
    }
    return NULL;
}

void PASER_rreq_list::clearTable(){
    //reset Table
    for (std::map<Uint128, packet_rreq_entry*>::iterator it = rreq_list.begin(); it != rreq_list.end(); it++) {
        packet_rreq_entry *temp = it->second;
        delete temp;
    }
    rreq_list.clear();
}

std::string PASER_rreq_list::detailedInfo(){
    std::stringstream out;
    out << "RREQ/RREP list:\n";
    for (std::map<Uint128, packet_rreq_entry*>::iterator it = rreq_list.begin(); it != rreq_list.end(); it++) {
        packet_rreq_entry *temp = it->second;
        out << "  IP: " << inet_ntoa(temp->dest_addr) << " retries: " << temp->tries << "\n";
    }
    return out.str();
}
