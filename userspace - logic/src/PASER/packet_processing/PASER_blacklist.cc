/**
 *\class  		PASER_blacklist
 *@brief       	Class provides a map of IP addresses to which a route was broken and a RERR message was sent.
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

#include "PASER_blacklist.h"

bool PASER_blacklist::setRerrTime(struct in_addr addr, struct timeval time){
    std::map<Uint128, struct timeval>::iterator it = rerr_list.find(addr.s_addr);
    if (it != rerr_list.end())
    {
        struct timeval last = it->second;
        if(time.tv_sec - last.tv_sec > 1){
            it->second.tv_sec = time.tv_sec;
            it->second.tv_usec = time.tv_usec;
            return true;
        }
        else if(time.tv_sec - last.tv_sec == 1 && time.tv_usec - last.tv_usec + 1000000 > PASER_TB_RERR_limit*1000){
            it->second.tv_sec = time.tv_sec;
            it->second.tv_usec = time.tv_usec;
            return true;
        }
        else if(time.tv_sec - last.tv_sec == 0 && time.tv_usec - last.tv_usec > PASER_TB_RERR_limit*1000){
            it->second.tv_sec = time.tv_sec;
            it->second.tv_usec = time.tv_usec;
            return true;
        }
        return false;
    }
    rerr_list.insert( std::make_pair(addr.s_addr, time));
    return true;
}

void PASER_blacklist::clearRerrList(){
    rerr_list.clear();
}

std::string PASER_blacklist::detailedInfo(){
    std::stringstream out;
    out << "Black list:\n";
    for (std::map<Uint128, struct timeval>::iterator it = rerr_list.begin(); it != rerr_list.end(); it++) {
        timeval temp = it->second;
        in_addr ip;
        ip.s_addr = it->first;
        out << " IP: " << inet_ntoa(ip) << " Time: sec: " << temp.tv_sec << " usec: " << temp.tv_usec << "\n";
    }
    return out.str();
}
