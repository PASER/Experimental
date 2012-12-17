/**
 *\class  		KDC_scheduler
 *@brief		Class implements the KDC's scheduler
 *
 *\authors    	Eugen.Paul | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http://www.kn.e-technik.tu-dortmund.de/
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

#include "KDCscheduler.h"

#include "../../PASER/packet_structure/PASER_GTKREQ.h"
#include "../../PASER/packet_structure/PASER_GTKREP.h"

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

#include <openssl/ssl.h>

#include <map>

KDC_scheduler::KDC_scheduler(KDC_config *KDC_config) {
    config = KDC_config;
    log = new PASER_syslog(config->getLogfile());
    crypto = new KDC_crypto_sign(config);

    socket = new KDC_socket(log,crypto);

}

KDC_scheduler::~KDC_scheduler() {
    delete socket;
    delete log;
    delete crypto;
}

void KDC_scheduler::scheduler() {
    fd_set rset;
    int maxFD;
    int numberOfRrequests = 0;

    while(isRunning) {
//    for (int j = 0; j < 10; j++) {
        // set FD_SET
        maxFD = socket->getServerSocketFD();
        FD_ZERO(&rset);
        FD_SET(socket->getServerSocketFD(), &rset);
        std::map<int, SSL*> socketMap = socket->getSocketMap();

        for (std::map<int, SSL*>::iterator it = socketMap.begin(); it != socketMap.end(); it++) {
            FD_SET(it->first, &rset);
            if (maxFD < it->first) {
                maxFD = it->first;
            }
        }

        maxFD++;

        // wait for data/connect
        timeval waiting;
        waiting.tv_sec = 2;
        waiting.tv_usec = 0;
        numberOfRrequests = select(maxFD, &rset, NULL, NULL, &waiting);
        if(!isRunning){
            break;
        }
        KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "select\n");

        if (numberOfRrequests <= 0) {
            continue;
        }

        KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "new connection\n");
        // new connection
        if (FD_ISSET(socket->getServerSocketFD(), &rset)) {
            KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "new connection accept\n");
            int tempSocket = socket->acceptConnection(socket->getServerSocketFD());
            if (tempSocket == -1) {
                continue;
            }
        }

        KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "socket map\n");
        // incoming data
        for (std::map<int, SSL*>::iterator it = socketMap.begin(); it != socketMap.end(); it++) {
            KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "socket map search\n");
            if(FD_ISSET(it->first, &rset)){
                KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "socket map found\n");
                processData(it->first);
            }
        }
        KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "end\n");

    } //for (;;)
    KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "IsRunning = FALSE\n");
}

void KDC_scheduler::processData(int fd) {
    lv_block packet = socket->readData(fd);
    if (packet.len == 0) {
        socket->closeConnection(fd);
        return;
    }

    PASER_GTKREQ * packetObj = PASER_GTKREQ::create(packet.buf, packet.len);
    if (!packetObj) {
        socket->closeConnection(fd);
        free(packet.buf);
        return;
    }
    free(packet.buf);
    KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming PASER_GTKREQ info:\n%s\n", packetObj->detailedInfo().c_str());

    if (!crypto->checkSignRequest(packetObj)) {
        socket->closeConnection(fd);
        return;
    }

    PASER_GTKREP *packetResp = crypto->generateGTKReasponse(packetObj);
    KDC_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Generated PASER_GTKREP info:\n%s\n", packetResp->detailedInfo().c_str());
    delete packetObj;

    lv_block packetToSend;
    int l = 0;
    packetToSend.len = 0;
    packetToSend.buf = NULL;
    packetToSend.buf = packetResp->getCompleteByteArray(&l);
    packetToSend.len = l;

    delete packetResp;
    if (l == 0) {
        socket->closeConnection(fd);
        return;
    }

    socket->writeData(fd, packetToSend);
    socket->closeConnection(fd);
}
