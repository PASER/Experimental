/**
 *\class  		PASER_timer_queue
 *@brief       	Class provides a list of node's timer.
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

#include "PASER_timer_queue.h"

PASER_timer_queue::~PASER_timer_queue(){
    for (std::list<PASER_timer_packet *>::iterator it = timer_queue.begin(); it!=timer_queue.end(); it++){
        PASER_timer_packet *temp = (PASER_timer_packet*)*it;
        delete temp;
    }
    timer_queue.clear();
}

bool compare_list(PASER_timer_packet *op1, PASER_timer_packet *op2){
    bool result = false;
    result = (
            (op1->timeout.tv_sec < op2->timeout.tv_sec) ||
            (
             (op1->timeout.tv_sec == op2->timeout.tv_sec) &&
             (op1->timeout.tv_usec < op2->timeout.tv_usec)
            )
            );
    return result;
}

void PASER_timer_queue::timer_sort(){
    timer_queue.sort(compare_list);
}

int PASER_timer_queue::timer_add(PASER_timer_packet *t){
    timer_remove(t);
    timer_queue.push_front(t);
    timer_queue.sort(compare_list);
    return 1;
}

int PASER_timer_queue::timer_remove(PASER_timer_packet *t){
	if(!t){
		return 0;
	}
	if(t->handler == KDC_REQUEST){
        for (std::list<PASER_timer_packet *>::iterator it=timer_queue.begin(); it!=timer_queue.end(); it++){
            PASER_timer_packet *temp = (PASER_timer_packet *)*it;
            if(temp->handler == KDC_REQUEST){
                timer_queue.erase(it);
                //We need to delete the package here, because no other pointer points to the object.
                delete temp;
                return 1;
            }
        }
	}
	if(t->handler == SSL_timer){
        for (std::list<PASER_timer_packet *>::iterator it=timer_queue.begin(); it!=timer_queue.end(); it++){
            PASER_timer_packet *temp = (PASER_timer_packet *)*it;
            if(temp->handler == SSL_timer && temp->sslFD == t->sslFD){
                timer_queue.erase(it);
                //We need to delete the package here, because no other pointer points to the object.
                delete temp;
                return 1;
            }
        }
	}
	else{
        for (std::list<PASER_timer_packet *>::iterator it=timer_queue.begin(); it!=timer_queue.end(); it++){
            PASER_timer_packet *temp = (PASER_timer_packet *)*it;
            if(temp->handler == ROUTINGTABLE_DELETE_ENTRY ||
                    temp->handler == ROUTINGTABLE_VALID_ENTRY ||
                    temp->handler == NEIGHBORTABLE_DELETE_ENTRY ||
                    temp->handler == NEIGHBORTABLE_VALID_ENTRY
                    ){
                if( temp->destAddr.s_addr == t->destAddr.s_addr &&
                    temp->handler == t->handler){
                    timer_queue.erase(it);
                    return 1;
                }
            }
            else{
                if( temp->destAddr.s_addr == t->destAddr.s_addr &&
                    temp->handler == t->handler){
                    timer_queue.erase(it);
                    return 1;
                }
            }
        }
        return 0;
	}
	return 0;
}

PASER_timer_packet *PASER_timer_queue::timer_get_next_timer(){
    if(timer_queue.size() == 0){
        return NULL;
    }
    return timer_queue.front();
}

long PASER_timer_queue::timeval_diff(struct timeval *t1, struct timeval *t2)
{
    long long res;
    if (t1 && t2)
    {
        res = t1->tv_sec;
        res = ((res - t2->tv_sec) * 1000000 + t1->tv_usec - t2->tv_usec) / 1000;
        return (long) res;
    }
    return -1;
}

std::string PASER_timer_queue::shortInfo(){
    std::stringstream out;
    out << "Timer Queue:\n";
    for (std::list<PASER_timer_packet *>::iterator it = timer_queue.begin(); it != timer_queue.end(); it++) {
        PASER_timer_packet *timerEntry = (PASER_timer_packet *)*it;
        out << " Timer Type: ";
        switch(timerEntry->handler){
        case KDC_REQUEST:
            out << "KDC_REQUEST";
            break;
        case ROUTE_DISCOVERY_UB:
            out << "ROUTE_DISCOVERY_UB";
            break;
        case ROUTINGTABLE_DELETE_ENTRY:
            out << "ROUTINGTABLE_DELETE_ENTRY";
            break;
        case ROUTINGTABLE_VALID_ENTRY:
            out << "ROUTINGTABLE_VALID_ENTRY";
            break;
        case NEIGHBORTABLE_DELETE_ENTRY:
            out << "NEIGHBORTABLE_DELETE_ENTRY";
            break;
        case NEIGHBORTABLE_VALID_ENTRY:
            out << "NEIGHBORTABLE_VALID_ENTRY";
            break;
        case TU_RREP_ACK_TIMEOUT:
            out << "TU_RREP_ACK_TIMEOUT";
            break;
        case HELLO_SEND_TIMEOUT:
            out << "HELLO_SEND_TIMEOUT";
            break;
        case PASER_ROOT:
            out << "PASER_ROOT";
            break;
        default:
            out << "UNKNOWN!!!";
            break;
        }
        out << " IP: " << inet_ntoa(timerEntry->destAddr);
        out << " Timer sec: " << timerEntry->timeout.tv_sec;
        out << " usec: " << timerEntry->timeout.tv_usec;
        out << "\n";
    }
    return out.str();
}

std::string PASER_timer_queue::detailedInfo(){
    return shortInfo();
}
