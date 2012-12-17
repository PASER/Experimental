/**
 *\class  		PASER_neighbor_entry
 *@brief       	Class represents an entry in the neighbor table
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

#include "PASER_neighbor_entry.h"
#include <openssl/x509.h>
#include <iomanip>

PASER_neighbor_entry::~PASER_neighbor_entry(){
    if (root){
        free(root);
    }
    root = NULL;

    if(Cert){
        X509_free((X509*)Cert);
    }
    Cert = NULL;
}

void PASER_neighbor_entry::setValidTimer(PASER_timer_packet *_validTimer){
	validTimer = _validTimer;
}

std::string PASER_neighbor_entry::detailedInfo(){
    std::stringstream out;
    out << "  Neighbor address: "<< inet_ntoa(neighbor_addr) << "\n";
    out << "  Flag: "<< neighFlag << "\n";
    if(root){
        out << "  Root: 0x";
        for (int i = 0; i < PASER_SECRET_HASH_LEN; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short)(unsigned char)root[i] << std::dec;
        }
        out << "\n";
    }
    else{
        out << "  Root element: UNKNOWN\n";
    }
    out << "  IV: "<< IV << "\n";
    out << "  Position.lat: " << position.lat << "\n";
    out << "  Position.lon: " << position.lon << "\n";
    if(Cert){
        out << "  Certificate: YES\n";
    }
    else{
        out << "  Certificate: UNKNOWN\n";
    }
    out << "  Is Valid: "<< (int)isValid << "\n";
    out << "  IF index: "<< ifIndex << "\n";
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
