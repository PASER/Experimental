/**
 *\class  		PASER_scheduler
 *@brief       	Class provides functions for working with PASERs scheduler.
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

#include "PASER_scheduler.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

PASER_scheduler::PASER_scheduler(PASER_global *paser_global) {
    pGlobal = paser_global;
}

PASER_scheduler::~PASER_scheduler() {

}

void PASER_scheduler::scheduler() {
    int maxFD = 0;
    int numberOfRrequests = 0;
    fd_set rset;

    // main Loop - endless
//#ifdef PASER_SOCKET_TEST
//    for (int j = 0; j < 40; j++) {
//#else
    extern bool isRunning;
    while(isRunning) {
//#endif
        pGlobal->UpdateTime();
        maxFD = 0;
        FD_ZERO(&rset);
        PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "Start scheduler step.\n");
        // add PASER Device sockets to select
        for (uint32_t i = 0; i < pGlobal->getPaser_configuration()->getNetDeviceNumber(); i++) {
            if (DEV_NR(i).enabled) {
                FD_SET(DEV_NR(i).sock, &rset);
                PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, " Add net device socket to select: %s\n", DEV_NR(i).ifname);
                if (maxFD < DEV_NR(i).sock) {
                    maxFD = DEV_NR(i).sock;
                }
            }
        }

        // add PASER Ethernet Device sockets to select
        std::map<int, SSL*> socketMap = pGlobal->getPASER_socket()->getSocketMap();
        for (std::map<int, SSL*>::iterator it = socketMap.begin(); it != socketMap.end(); it++) {
            PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, " Add net SSL socket to select: %d\n", it->first);
            FD_SET(it->first, &rset);
            if (maxFD < it->first) {
                maxFD = it->first;
            }
        }

        FD_SET(pGlobal->getPASER_socket()->getSocketToKernel(), &rset);
        if (maxFD < pGlobal->getPASER_socket()->getSocketToKernel()) {
            maxFD = pGlobal->getPASER_socket()->getSocketToKernel();
        }

        maxFD++;

        // get next Timeout
        timeval timeEvent;
        timeval diff;
        if (pGlobal->getTimer_queue()->timer_get_next_timer() != NULL) {
            timeEvent = pGlobal->getTimer_queue()->timer_get_next_timer()->timeout;
            timeval now;
            pGlobal->getPASERtimeofday(&now);
            // calculate time to next timeout (next - now)
//            PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "next timeout: sec:%ld, usec: %ld\n", timeEvent.tv_sec, timeEvent.tv_usec);
//            PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "now  timeout: sec:%ld, usec: %ld\n", now.tv_sec, now.tv_usec);
            diff = timeDiff(timeEvent, now);
            // wait for data/connect/timeouts...
            PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "select timeout: sec:%ld, usec: %ld\n", diff.tv_sec, diff.tv_usec);
            numberOfRrequests = select(maxFD, &rset, NULL, NULL, &diff);
        } else {
            // wait for data/connect/timeouts...
            timeval waiting;
            waiting.tv_sec = 2;
            waiting.tv_usec = 0;
            PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "select timeout: waiting\n");
            numberOfRrequests = select(maxFD, &rset, NULL, NULL, &waiting);
        }
        if(!isRunning){
            break;
        }
        pGlobal->UpdateTime();

        if (numberOfRrequests < 0) {
            // print ERROR
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "select failed: (%d)%s\n", errno, strerror( errno ));
            continue;
        }

        // check PASER PASER Device sockets
        for (uint32_t i = 0; i < pGlobal->getPaser_configuration()->getNetDeviceNumber(); i++) {
            if (DEV_NR(i).enabled) {
                if (FD_ISSET(DEV_NR(i).sock, &rset)) {
                    lv_block data = pGlobal->getPASER_socket()->readDataFromNetwork(&(DEV_NR(i)));
                    PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "Read data from PASER device: %s\n", DEV_NR(i).ifname);
                    if (data.len != -1) {
                        pGlobal->getPacket_processing()->handleLowerMsg(data.buf, data.len, DEV_NR(i).ifindex);
                    }
                }
            }
        }

        // check PASER Ethernet Device sockets
        for (std::map<int, SSL*>::iterator it = socketMap.begin(); it != socketMap.end(); it++) {
            if (FD_ISSET(it->first, &rset)) {
                lv_block data = pGlobal->getPASER_socket()->readDataFromSSL(it->first);
                PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "Read data from SSL socket: %d\n", it->first);
                if (data.len == 0) {
                    //close SSL Socket
                    PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "Close SSL socket: %d\n", it->first);
                    pGlobal->getPASER_socket()->closeSSLSocket(it->first);
                    continue;
                }
                pGlobal->getPacket_processing()->handleLowerMsg(data.buf, data.len, ETHDEV_NR(0).ifindex);
            }
        }

        // check kernel Socket
        if(FD_ISSET(pGlobal->getPASER_socket()->getSocketToKernel(), &rset)){
            lv_block data = pGlobal->getPASER_socket()->readDataFromKernel();
            PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "Read data from Kernel Socket\n");
            if(data.len > 0){
            	free(data.buf);
            }
        }

//        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "%s",pGlobal->getTimer_queue()->detailedInfo().c_str());
//        PASER_LOG_WRITE_LOG(PASER_LOG_TIMEOUT_INFO, "%s",pGlobal->getNeighbor_table()->detailedInfo().c_str());
        walk_timers();
    }

}

timeval PASER_scheduler::timeDiff(timeval t1, timeval t2) {
    timeval diff;
    diff.tv_sec = t1.tv_sec - t2.tv_sec;
    diff.tv_usec = t1.tv_usec - t2.tv_usec;
    if (diff.tv_sec < 0 || (diff.tv_sec == 0 && diff.tv_usec < 0)) {
        diff.tv_sec = 0;
        diff.tv_usec = 0;
    } else if (diff.tv_usec < 0) {
        diff.tv_usec = diff.tv_usec + 1000000;
        diff.tv_sec--;
    }
    return diff;
}

void PASER_scheduler::walk_timers() {
    while (1) {
        if (pGlobal->getTimer_queue()->timer_get_next_timer() == NULL) {
            return;
        }
        timeval nextEvent = pGlobal->getTimer_queue()->timer_get_next_timer()->timeout;
        timeval now;
        pGlobal->getPASERtimeofday(&now);
        timeval timeToEvent = timeDiff(nextEvent, now);
        PASER_LOG_WRITE_LOG(PASER_LOG_SCHEDULER, "walk_timers: timeToEvent = sec: %ld, usec: %ld\n",
                timeToEvent.tv_sec, timeToEvent.tv_usec);
        if (timeToEvent.tv_sec != 0 || timeToEvent.tv_usec != 0) {
            return;
        }
        pGlobal->getRoute_maintenance()->handleSelfMsg();
    }
}
