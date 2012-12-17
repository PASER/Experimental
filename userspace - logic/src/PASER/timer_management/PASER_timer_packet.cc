/**
 *\class  		PASER_timer_packet
 *@brief       	Class represents an entry in the timer queue
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

#include "PASER_timer_packet.h"
#include "../packet_structure/PASER_UB_RREQ.h"
#include "../packet_structure/PASER_UU_RREP.h"

PASER_timer_packet::PASER_timer_packet(){
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    destAddr.s_addr = 0;
    data = NULL;
}

PASER_timer_packet::~PASER_timer_packet(){
    if(data){
        PASER_UB_RREQ *pack0;
        PASER_UU_RREP *pack1;
        switch (handler) {
            case ROUTE_DISCOVERY_UB:
                pack0 = (PASER_UB_RREQ *)data;
                delete pack0;
                data = NULL;
                break;
            case TU_RREP_ACK_TIMEOUT:
                pack1 = (PASER_UU_RREP *)data;
                delete pack1;
                data = NULL;
                break;
            default:
                break;
        }
    }
}

bool PASER_timer_packet::operator==(PASER_timer_packet *op2){
    return (
            destAddr.s_addr == op2->destAddr.s_addr &&
            handler == op2->handler
            );
}

