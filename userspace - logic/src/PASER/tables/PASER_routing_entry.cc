/**
 *\class  		PASER_routing_entry
 *@brief       	Class represents an entry in the routing table
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

#include "PASER_routing_entry.h"
#include <openssl/x509.h>

PASER_routing_entry::~PASER_routing_entry(){
    if(Cert){
//        free(Cert);
        X509_free((X509*)Cert);
    }
    Cert = NULL;
}

bool PASER_routing_entry::operator ==(PASER_routing_entry ent){
	if (//ent.AddL == AddL &&
		//ent.Cert == Cert &&
		//ent.deltimer == deltimer &&
		ent.dest_addr.s_addr == dest_addr.s_addr &&
		ent.hopcnt == hopcnt &&
//		ent.ifindex == ifindex &&
		ent.is_gw == is_gw &&
		ent.nxthop_addr.s_addr == nxthop_addr.s_addr
		//ent.seqnum == seqnum
		//ent.validtimer == validtimer
		)
	{
		return true;
	}
	return false;
}

void PASER_routing_entry::setValidTimer(PASER_timer_packet *_validTimer){
	validTimer = _validTimer;
}

std::string PASER_routing_entry::detailedInfo(){
    std::stringstream out;
    out << "  Destination address: "<< inet_ntoa(dest_addr) << "\n";
    out << "  Next hop address: "<< inet_ntoa(nxthop_addr) << "\n";
    out << "  Sequence: "<< seqnum << "\n";
    out << "  Hop count: "<< (int)hopcnt << "\n";
    out << "  Is Gateway: "<< (int)is_gw << "\n";
    out << "  Is Valid: "<< (int)isValid << "\n";

    out << "  Address Range List:\n";
    for(std::list<address_range>::iterator it=AddL.begin(); it!=AddL.end(); it++){
        address_range temp = (address_range)*it;
        out << "  - IP: " << inet_ntoa(temp.ipaddr);
        out << " Mask: " << inet_ntoa(temp.mask) << "\n";
    }

    if(Cert){
        out << "  Certificate: YES\n";
    }
    else{
        out << "  Certificate: UNKNOWN\n";
    }
    if(deleteTimer){
        out << "  Delete Timer: sec:" << deleteTimer->timeout.tv_sec << " usec:" << deleteTimer->timeout.tv_usec << "\n";
    }
    else{
        out << "  Delete Timer: UNKNOWN\n";
    }
    if(validTimer){
        out << "  Valid Timer: sec:" << validTimer->timeout.tv_sec << " usec:" << validTimer->timeout.tv_usec << "\n";
    }
    else{
        out << "  Valid Timer: UNKNOWN\n";
    }
    return out.str();
}
