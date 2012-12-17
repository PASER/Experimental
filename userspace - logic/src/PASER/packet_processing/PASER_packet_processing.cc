/**
 *\class  		PASER_packet_processing
 *@brief      	Class provides functions for working with all PASER messages.
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

#include "PASER_packet_processing.h"

#include "../packet_structure/PASER_MSG.h"
#include "../packet_structure/PASER_B_ROOT.h"
#include "../packet_structure/PASER_TB_HELLO.h"
#include "../packet_structure/PASER_TB_RERR.h"
#include "../packet_structure/PASER_RESET.h"
#include "../packet_structure/PASER_TU_RREP.h"
#include "../packet_structure/PASER_TU_RREP_ACK.h"
#include "../packet_structure/PASER_TU_RREQ.h"
#include "../packet_structure/PASER_UB_RREQ.h"
#include "../packet_structure/PASER_UU_RREP.h"
#include "../packet_structure/PASER_GTKREQ.h"
#include "../packet_structure/PASER_GTKREP.h"
#include "../packet_structure/PASER_GTKRESET.h"

#include <math.h>
#define DEG_TO_RAD  0.0174532925199432958

//#define TIMEMEASUREMENT

#ifdef TIMEMEASUREMENT
#include <sys/time.h>
#endif

PASER_packet_processing::PASER_packet_processing(PASER_global *paser_global, PASER_config *pConfig) {
    pGlobal = paser_global;
    paser_configuration = NULL;
    timer_queue = NULL;
    routing_table = NULL;
    neighbor_table = NULL;
    route_findung = NULL;
    rreq_list = NULL;
    rrep_list = NULL;
    root = NULL;
    crypto_sign = NULL;
    crypto_hash = NULL;
    netDevice = NULL;
    packet_sender = NULL;
}

void PASER_packet_processing::init() {
    paser_configuration = pGlobal->getPaser_configuration();
    timer_queue = pGlobal->getTimer_queue();
    routing_table = pGlobal->getRouting_table();
    neighbor_table = pGlobal->getNeighbor_table();
//    packet_queue = pGlobal->getPacket_queue();
    route_findung = pGlobal->getRoute_findung();
    rreq_list = pGlobal->getRreq_list();
    rrep_list = pGlobal->getRrep_list();
    root = pGlobal->getRoot();
    crypto_sign = pGlobal->getCrypto_sign();
    crypto_hash = pGlobal->getCrypto_hash();
    netDevice = paser_configuration->getNetDevice();
    packet_sender = pGlobal->getPacketSender();
}

PASER_packet_processing::~PASER_packet_processing() {

}

void PASER_packet_processing::handleLowerMsg(uint8_t *s, int length, u_int32_t ifIndex) {
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming Packet. Try to cast it into PASER packet.\n");
#ifdef TIMEMEASUREMENT
    struct timeval a;
    struct timeval b;
    gettimeofday(&a, NULL);
#endif
    PASER_MSG *msg = castToPaserPacket(s, length);

    if (!msg) {
        free(s);
        return;
    }
    switch (msg->type) {
    case 0:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_UB_RREQ\n");
        handleUBRREQ(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleUBRREQ: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 1:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_UU_RREP\n");
        handleUURREP(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleUURREP: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 2:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_TU_RREQ\n");
        handleTURREQ(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleTURREQ: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 3:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_TU_RREP\n");
        handleTURREP(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleTURREP: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 4:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_TU_RREP_ACK\n");
        handleTURREPACK(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleTURREPACK: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 5:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_TB_RERR\n");
        handleRERR(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleRERR: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 6:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_TB_HELLO\n");
        handleHELLO(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleHELLO: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 7:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_B_ROOT\n");
        handleB_ROOT(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleB_ROOT: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 8:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming PASER_B_RESET\n");
        handleB_RESET(msg, ifIndex);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleB_RESET: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    case 10:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Incoming KDC_Message\n");
        handleKDCReply(msg);
#ifdef TIMEMEASUREMENT
        gettimeofday(&b, NULL);
        PASER_LOG_WRITE_LOG(0,"myStats: handleKDCReply: b-a=%ld.%6ld\n", b.tv_usec-a.tv_usec>0?b.tv_sec-a.tv_sec:b.tv_sec-a.tv_sec-1, b.tv_usec-a.tv_usec>0?b.tv_usec-a.tv_usec:b.tv_usec-a.tv_usec+1000000);
#endif
        break;
    default:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "false PASER Packet type\n");
        free(s);
        delete msg;
        return;
    }
    free(s);
}

PASER_MSG *PASER_packet_processing::castToPaserPacket(uint8_t *s, int length) {
    if (length <= 0 || s == NULL) {
        return NULL;
    }
    uint8_t type = s[0];
    switch (type) {
    case 0x00:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate UB-RREQ\n");
        return PASER_UB_RREQ::create(s, length);
        break;
    case 0x01:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate UU-RREP\n");
        return PASER_UU_RREP::create(s, length);
        break;
    case 0x02:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate TU-RREQ\n");
        return PASER_TU_RREQ::create(s, length);
        break;
    case 0x03:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate TU-RREP\n");
        return PASER_TU_RREP::create(s, length);
        break;
    case 0x04:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate TU-RREP-ACK\n");
        return PASER_TU_RREP_ACK::create(s, length);
        break;
    case 0x05:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate RERR\n");
        return PASER_TB_RERR::create(s, length);
        break;
    case 0x06:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate HELLO\n");
        return PASER_TB_HELLO::create(s, length);
        break;
    case 0x07:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate B-ROOT\n");
        return PASER_B_ROOT::create(s, length);
        break;
    case 0x08:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate RESET\n");
        return PASER_RESET::create(s, length);
        break;
    case 0x09:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate GTK-Request\n");
        return PASER_GTKREQ::create(s, length);
        break;
    case 0x0a:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate GTK-Response\n");
        return PASER_GTKREP::create(s, length);
        break;
    case 0x0b:
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Try to generate GTK-Reset\n");
        return PASER_GTKRESET::create(s, length);
        break;
    default:
        return NULL;
    }
}

int PASER_packet_processing::check_seq_nr(PASER_MSG *paser_msg, struct in_addr forwarding) {
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "Check sequence number...");
    PASER_routing_entry *srcNode = NULL;
    struct in_addr destAddr;
    // beim UB_RREQ und TU_RREQ Paketen wird nicht nur die Sequenznummer des Absenders, sondern auch die
    // Sequenznummer des Knotens ueberprueft, das das Paket weitergeleitet hat.
    if (paser_msg->type == UB_RREQ || paser_msg->type == TU_RREQ) {
        u_int32_t seqForw = 0;
        if (paser_msg->type == UB_RREQ) {
            PASER_UB_RREQ *ubrreq_msg = dynamic_cast<PASER_UB_RREQ *>(paser_msg);
            seqForw = ubrreq_msg->seqForw;
        } else {
            PASER_TU_RREQ *turreq_msg = dynamic_cast<PASER_TU_RREQ *>(paser_msg);
            seqForw = turreq_msg->seqForw;
        }
        srcNode = routing_table->findDest(paser_msg->srcAddress_var);
        destAddr.s_addr = paser_msg->destAddress_var.s_addr;

        PASER_routing_entry *forwardingNode = routing_table->findDest(forwarding);
        if (srcNode && paser_configuration->getIsGW()
                && (destAddr.s_addr == 0xFFFFFFFF || paser_configuration->isAddInMyLocalAddress(destAddr)) && forwardingNode) {
            if ((paser_msg->seq == srcNode->seqnum || pGlobal->isSeqNew(srcNode->seqnum, paser_msg->seq))
                    && pGlobal->isSeqNew(forwardingNode->seqnum, seqForw)) {
                PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
                return 1;
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
                return 0;
            }
        }
        if (srcNode && paser_configuration->isAddInMyLocalAddress(destAddr) && forwardingNode) {
            if ((paser_msg->seq == srcNode->seqnum || pGlobal->isSeqNew(srcNode->seqnum, paser_msg->seq))
                    && pGlobal->isSeqNew(forwardingNode->seqnum, seqForw)) {
                PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
                return 1;
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
                return 0;
            }
        }
        if (srcNode && !paser_configuration->isAddInMyLocalAddress(destAddr) && forwardingNode) {
            if (pGlobal->isSeqNew(srcNode->seqnum, paser_msg->seq) && pGlobal->isSeqNew(forwardingNode->seqnum, seqForw)) {
                PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
                return 1;
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
                return 0;
            }
        }
        if (!srcNode && forwardingNode) {
            if (pGlobal->isSeqNew(forwardingNode->seqnum, seqForw)) {
                PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
                return 1;
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
                return 0;
            }
        }
        if (srcNode && !forwardingNode) {
            if (pGlobal->isSeqNew(srcNode->seqnum, paser_msg->seq) || paser_msg->seq == srcNode->seqnum) {
                PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
                return 1;
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
                return 0;
            }
        }
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
        return 1;
    } else if (paser_msg->type == UU_RREP || paser_msg->type == TU_RREP) {
        srcNode = routing_table->findDest(paser_msg->destAddress_var);
        if (srcNode) {
            if (pGlobal->isSeqNew(srcNode->seqnum, paser_msg->seq)) {
                PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
                return 1;
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE. Old = %d, New = %d\n", srcNode->seqnum, paser_msg->seq);
                return 0;
            }
        }
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
        return 1;
    } else if (paser_msg->type == TU_RREP_ACK || paser_msg->type == B_RERR || paser_msg->type == B_HELLO || paser_msg->type == B_ROOT) {
        srcNode = routing_table->findDest(paser_msg->srcAddress_var);
        if (srcNode) {
            if (pGlobal->isSeqNew(srcNode->seqnum, paser_msg->seq)) {
                PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
                return 1;
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
                return 0;
            }
        }
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
        return 1;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
    return 0;
}

int PASER_packet_processing::check_geo(geo_pos position) {
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "Check distance to the node...");
    geo_pos myGeo = pGlobal->getGeoPosition();

//    double dx = 71.5 * (myGeo.lon - position.lon);
//    double dy = 111.3 * (myGeo.lat - position.lat);

//    double temp = sqrt(dx * dx + dy * dy);
    double temp = 6378.388 * acos(sin(myGeo.lat*DEG_TO_RAD) * sin(position.lat*DEG_TO_RAD) + cos(myGeo.lat*DEG_TO_RAD) * cos(position.lat*DEG_TO_RAD) * cos((position.lon - myGeo.lon)*DEG_TO_RAD));
//    double temp = sqrt((position.lat - myGeo.lat) * (position.lat - myGeo.lat) + (position.lon - myGeo.lon) * (position.lon - myGeo.lon));

    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING,
            "Own Position lat: %f, lon: %f, Node Position lat: %f, lon: %f\nDistance: %f, Max Distance: %f",
            myGeo.lat, myGeo.lon, position.lat, position.lon, temp, PASER_radius);
    if (temp > PASER_radius) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, " FALSE\n");
        return 0;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, " OK\n");
    return 1;
}

int PASER_packet_processing::checkRouteList(std::list<address_list> rList) {
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "Check route list...");
    for (std::list<address_list>::iterator it = rList.begin(); it != rList.end(); it++) {
        if (paser_configuration->isAddInMyLocalAddress(((address_list) *it).ipaddr)) {
            PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
            return 1;
        }
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
    return 0;
}

void PASER_packet_processing::handleUBRREQ(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_UB_RREQ *ubrreq_msg = dynamic_cast<PASER_UB_RREQ *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete ubrreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", ubrreq_msg->detailedInfo().c_str());

    if (checkRouteList(ubrreq_msg->AddressRangeList)) {
        delete ubrreq_msg;
        return;
    }
    struct in_addr forwarding = ubrreq_msg->AddressRangeList.back().ipaddr;
    //Pruefe Sequenznummer des Pakets
    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), forwarding)) {
        delete ubrreq_msg;
        return;
    }
    //Pruefe GeoPosition des Absenders
    if (!check_geo(ubrreq_msg->geoForwarding)) {
        delete ubrreq_msg;
        return;
    }

    //pruefe Timestamp
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Timestamp...");
    if (now.tv_sec - ubrreq_msg->timestamp > PASER_time_diff || now.tv_sec - ubrreq_msg->timestamp < -PASER_time_diff) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
        delete ubrreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    //Pruefe Signatur des Pakets
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature.\n");
    if (!crypto_sign->checkSignUBRREQ(ubrreq_msg)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...FALSE\n");
        delete ubrreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...OK\n");

    //pruefe keyNr
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check GTK number...");
    if (ubrreq_msg->keyNr != pGlobal->getKeyNr() && ubrreq_msg->keyNr != 0) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\nSend RESET.\n");
        packet_sender->send_reset();
        delete ubrreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    //aktualisiere NeighborTable
    X509 *certNeigh = crypto_sign->extractCert(ubrreq_msg->certForw);
    neighbor_table->updateNeighborTableAndSetTableTimeout(forwarding, 0, ubrreq_msg->root, ubrreq_msg->initVector,
            ubrreq_msg->geoForwarding, certNeigh, now, ifIndex);

    //aktualisiere RoutingTable mit der Information ueber den Nachbar
    std::list<address_range> addList(ubrreq_msg->AddressRangeList.back().range);
    X509 *certForw = crypto_sign->extractCert(ubrreq_msg->certForw);
    routing_table->updateRoutingTableAndSetTableTimeout(addList, forwarding, ubrreq_msg->seqForw, certForw, forwarding, 0, ifIndex, now,
            crypto_sign->isGwCert(certForw), false);

    //aktualisiere RoutingTable mit der Information des Absenders
    X509 *cert = NULL;
    if (ubrreq_msg->GFlag) {
        cert = crypto_sign->extractCert(ubrreq_msg->cert);
        if (cert != NULL && crypto_sign->checkOneCert(cert) == 0) {
            X509_free(cert);
            delete ubrreq_msg;
            return;
        }
    }
    routing_table->updateRoutingTableAndSetTableTimeout(ubrreq_msg->AddressRangeList.front().range, ubrreq_msg->srcAddress_var,
            ubrreq_msg->seq, cert, forwarding, ubrreq_msg->metricBetweenQueryingAndForw, ifIndex, now, crypto_sign->isGwCert(cert), false);

    PASER_routing_entry *rEntry = routing_table->findDest(ubrreq_msg->srcAddress_var);
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);

    //Aktualisiere die RoutingTabele mit der Informationen ueber alle Knoten, die die Nachricht weitergeleitet haben
    if (nEntry && nEntry->neighFlag && nEntry->isValid) {
        routing_table->updateRoutingTable(now, ubrreq_msg->AddressRangeList, forwarding, ifIndex);
    }

    //Verschicke alle Pakete, die zwischen gespeichert sind
    if (nEntry && nEntry->neighFlag && nEntry->isValid) {
        // send packets
        struct in_addr netmask;
        netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        routing_table->updateKernelRoutingTable(ubrreq_msg->srcAddress_var, rEntry->nxthop_addr, netmask, rEntry->hopcnt, false,
                nEntry->ifIndex);
        deleteRouteRequestTimeout(ubrreq_msg->srcAddress_var);
        pGlobal->getPASER_socket()->releaseQueue(ubrreq_msg->srcAddress_var, netmask);
//        packet_queue->send_queued_packets(ubrreq_msg->srcAddress_var);

        deleteRouteRequestTimeoutForAddList(ubrreq_msg->AddressRangeList);
        pGlobal->getPASER_socket()->releaseQueue_for_AddList(ubrreq_msg->AddressRangeList);

//        packet_queue->send_queued_packets_for_AddList(ubrreq_msg->AddressRangeList);
    }

    int ifId = paser_configuration->getIfIdFromIfIndex(ifIndex);
    // sende RREP
    if ((paser_configuration->getIsGW() && ubrreq_msg->destAddress_var.s_addr == PASER_BROADCAST )
    || (paser_configuration->isAddInMyLocalAddress(ubrreq_msg->destAddress_var) && ifId >= 0
            && (netDevice[ifId].ipaddr.s_addr == ubrreq_msg->destAddress_var.s_addr))
    || (paser_configuration->isAddInMySubnetwork(ubrreq_msg->destAddress_var))
    || (paser_configuration->getIsGW() && ubrreq_msg->destAddress_var.s_addr == 0)){
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "I am a destination\n");
    // uu-rrep
    if (paser_configuration->getIsGW() && ubrreq_msg->GFlag) {
        //sende anfrage an KDC
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forward request to KDC. Generate GTK Request.\n");
        packet_sender->sendKDCRequest(ubrreq_msg->srcAddress_var, forwarding, ubrreq_msg->cert, ubrreq_msg->nonce);
        delete ubrreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Generate UU-RREP.\n");
    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(forwarding);
    ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = netDevice[ifId].ipaddr.s_addr;
    cert = (X509*) rEntry->Cert;
    kdc_block kdcData;
    PASER_UU_RREP *packet = packet_sender->send_uu_rrep(ubrreq_msg->srcAddress_var, forwarding, WlanAddrStruct/*myAddrStruct*/,
            ubrreq_msg->GFlag, cert, kdcData);
    packet_rreq_entry *rrep = rrep_list->pending_find(forwarding);
    if (rrep) {
        timer_queue->timer_remove(rrep->tPack);
        delete rrep->tPack;
    } else {
        rrep = rrep_list->pending_add(forwarding);
    }
    rrep->tries = 0;

    PASER_timer_packet *tPack = new PASER_timer_packet();
    tPack->data = (void *) packet;
    tPack->destAddr.s_addr = forwarding.s_addr;
    tPack->handler = TU_RREP_ACK_TIMEOUT;
    tPack->timeout = timeval_add(now, PASER_UU_RREP_WAIT_TIME);

    timer_queue->timer_add(tPack);
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Set TU_RREP_ACK_TIMEOUT. Sec: %d, usec: %d\n",
            (int)tPack->timeout.tv_sec, (int)tPack->timeout.tv_usec);
    rrep->tPack = tPack;
}
// leite die Nachricht weiter
else if (!paser_configuration->isAddInMyLocalAddress(ubrreq_msg->destAddress_var)) {
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forwarding UB_RREQ\n");
    PASER_routing_entry *routeToDest = NULL;
    if (ubrreq_msg->destAddress_var.s_addr == 0xFFFFFFFF || ubrreq_msg->destAddress_var.s_addr == 0x00000000) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Destination is GW.\n");
        routeToDest = routing_table->getRouteToGw();
    } else {
        routeToDest = routing_table->findDest(ubrreq_msg->destAddress_var);
        if (!routeToDest) {
            routeToDest = routing_table->findAdd(ubrreq_msg->destAddress_var);
            if (routeToDest) {
                ubrreq_msg->destAddress_var = routeToDest->dest_addr;
            }
        }
    }
    PASER_neighbor_entry *neighToDest = NULL;
    if (routeToDest != NULL && routeToDest->isValid) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Route to destination node is valid\n");
        neighToDest = neighbor_table->findNeigh(routeToDest->nxthop_addr);
    } else {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Route to destination node is invalid\n");
    }

    //Falls nexhop bekannt und vertraulich ist, dann sende TURREQ, sonst UBRREQ
    if (neighToDest != NULL && neighToDest->isValid && neighToDest->neighFlag) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Generate and send TU-RREQ\n");
        if (forwarding.s_addr != routeToDest->nxthop_addr.s_addr) {
            PASER_TU_RREQ *newPacket = packet_sender->forward_ub_rreq_to_tu_rreq(ubrreq_msg, routeToDest->nxthop_addr,
                    routeToDest->dest_addr);
            delete newPacket;
        }
        else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "set old route invalid, generate and send UB-RREQ\n");
            routeToDest->isValid = 0;
            routeToDest->validTimer = NULL;
            PASER_neighbor_entry *nEntry = pGlobal->getNeighbor_table()->findNeigh(routeToDest->dest_addr);
            if (nEntry != NULL) {
                PASER_timer_packet* valTime = nEntry->validTimer;
                if (valTime) {
                    pGlobal->getTimer_queue()->timer_remove(valTime);
                    delete valTime;
                }
                nEntry->validTimer = NULL;
            }
            pGlobal->getTimer_queue()->timer_remove(routeToDest->validTimer);
            delete routeToDest->validTimer;
            // if the node a neighbor is make all Routes over the node invalid and delete it from kernel routing table
            pGlobal->getRouting_table()->deleteFromKernelRoutingTableNodesWithNextHopAddr(routeToDest->dest_addr);
            PASER_routing_entry *routeToGW = pGlobal->getRouting_table()->findBestGW();
            if (routeToGW == NULL && !paser_configuration->getIsGW() && paser_configuration->isGWsearch() && !pGlobal->getWasRegistered()) {
                pGlobal->setIsRegistered(false);
                pGlobal->getRoute_findung()->tryToRegister();
            }
            // ub-rreq
            PASER_UB_RREQ *newPacket = packet_sender->forward_ub_rreq(ubrreq_msg);
            if (newPacket != NULL) {
                delete newPacket;
            }
        }
    } else {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Generate and send UB-RREQ\n");
        // ub-rreq
        PASER_UB_RREQ *newPacket = packet_sender->forward_ub_rreq(ubrreq_msg);
        if (newPacket != NULL) {
            delete newPacket;
        }
    }
}

    delete ubrreq_msg;
}

void PASER_packet_processing::handleUURREP(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_UU_RREP *uurrep_msg = dynamic_cast<PASER_UU_RREP *>(msg);
    if (((!paser_configuration->isAddInMyLocalAddress(uurrep_msg->srcAddress_var)
            || (paser_configuration->isAddInMyLocalAddress(uurrep_msg->srcAddress_var) && !uurrep_msg->GFlag))
            && !pGlobal->getWasRegistered())) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered and wrong destination.\n");
        delete uurrep_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", uurrep_msg->detailedInfo().c_str());

    if (checkRouteList(uurrep_msg->AddressRangeList)) {
        delete uurrep_msg;
        return;
    }

    struct in_addr forwarding = uurrep_msg->AddressRangeList.back().ipaddr;
    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), forwarding)) {
        delete uurrep_msg;
        return;
    }

    if (!check_geo(uurrep_msg->geoForwarding)) {
        delete uurrep_msg;
        return;
    }

    //pruefe Timestamp

    struct timeval now;
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Timestamp...");
    pGlobal->getPASERtimeofday(&now);
    if (now.tv_sec - uurrep_msg->timestamp > PASER_time_diff || now.tv_sec - uurrep_msg->timestamp < -PASER_time_diff) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
        delete uurrep_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    // read KDC
    if (uurrep_msg->GFlag && paser_configuration->isAddInMyLocalAddress(uurrep_msg->srcAddress_var)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Nonce...");
        if (pGlobal->getLastGwSearchNonce() != uurrep_msg->kdc_data.nonce) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
            delete uurrep_msg;
            return;
        }
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "OK\n");

        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check KDC Signature.\n");
        if (crypto_sign->checkSignKDC(uurrep_msg->kdc_data) != 1) {
            delete uurrep_msg;
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check KDC Signature...FALSE\n");
            return;
        }
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check KDC Signature...OK\n");

        lv_block gtk;
        gtk.len = 0;
        gtk.buf = NULL;
        crypto_sign->rsa_dencrypt(uurrep_msg->kdc_data.GTK, &gtk);
        pGlobal->setGTK(gtk);
        if (gtk.len > 0) {
            free(gtk.buf);
        }
        //speichere neuen Zertifikat und Signatur von RESET
        pGlobal->setKDC_cert(uurrep_msg->kdc_data.cert_kdc);
        pGlobal->setRESET_sign(uurrep_msg->kdc_data.sign_key);
        pGlobal->setKeyNr(uurrep_msg->kdc_data.key_nr);
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature.\n");
    if (!crypto_sign->checkSignUURREP(uurrep_msg)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...FALSE\n");
        delete uurrep_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...OK\n");

    //pruefe keyNr
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check GTK number...");
    if (uurrep_msg->keyNr != pGlobal->getKeyNr()) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\nSend RESET.\n");
        packet_sender->send_reset();
        delete uurrep_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");
    //update Neighbor Table
    X509 *certNeigh = crypto_sign->extractCert(uurrep_msg->certForw);
    neighbor_table->updateNeighborTableAndSetTableTimeout(forwarding, 1, uurrep_msg->root, uurrep_msg->initVector,
            uurrep_msg->geoForwarding, certNeigh, now, ifIndex);

    //update Routing Table with forwarding Node
    std::list<address_range> addList(uurrep_msg->AddressRangeList.back().range);
    X509 *certForw = crypto_sign->extractCert(uurrep_msg->certForw);
    routing_table->updateRoutingTableAndSetTableTimeout(addList, forwarding,
    /*uurrep_msg->seqForw,*/0, certForw, forwarding, 0, ifIndex, now, crypto_sign->isGwCert(certForw), true);

    //update Routing Table
//    std::list<address_range> EmptyAddList( uurrep_msg->AddressRangeList.front().range );
    routing_table->updateRoutingTableAndSetTableTimeout(uurrep_msg->AddressRangeList.front().range, uurrep_msg->destAddress_var,
            uurrep_msg->seq, NULL, forwarding, uurrep_msg->metricBetweenDestAndForw, ifIndex, now,
            uurrep_msg->GFlag || uurrep_msg->searchGW, true);

    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(forwarding);

    if (nEntry && nEntry->neighFlag && nEntry->isValid) {
        routing_table->updateRoutingTable(now, uurrep_msg->AddressRangeList, forwarding, ifIndex);
    }

    // send TU-RREP-ACK
    in_addr WlanAddrStruct;
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = netDevice[ifId].ipaddr.s_addr;
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send TU-RREP-ACK\n");
    PASER_TU_RREP_ACK * turrepack = packet_sender->send_tu_rrep_ack(WlanAddrStruct, forwarding);
    delete turrepack;

    if (uurrep_msg->GFlag) {
        pGlobal->setIsRegistered(true);
        pGlobal->setWasRegistered(true);
    }

    // delete TIMEOUT
    if (uurrep_msg->GFlag == 0x01) {
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0xFFFFFFFF;
        deleteRouteRequestTimeout(bcast_addr);
    }
    if (uurrep_msg->searchGW == 0x01) {
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0x00000000;
        deleteRouteRequestTimeout(bcast_addr);
    }
    // send packets
    if (uurrep_msg->searchGW == 0x01) {
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0x00000000;
        struct in_addr netmask;
        netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        pGlobal->getPASER_socket()->releaseQueue(bcast_addr, netmask);
    }
    deleteRouteRequestTimeout(uurrep_msg->destAddress_var);
    struct in_addr netmask;
    netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
    pGlobal->getPASER_socket()->releaseQueue(uurrep_msg->destAddress_var, netmask);
//    packet_queue->send_queued_packets(uurrep_msg->destAddress_var);
    deleteRouteRequestTimeoutForAddList(uurrep_msg->AddressRangeList);
    pGlobal->getPASER_socket()->releaseQueue_for_AddList(uurrep_msg->AddressRangeList);
//    packet_queue->send_queued_packets_for_AddList(uurrep_msg->AddressRangeList);

    if (!paser_configuration->isAddInMyLocalAddress(uurrep_msg->srcAddress_var)) {
        PASER_routing_entry *rEntry = routing_table->findDest(uurrep_msg->srcAddress_var);
        if (rEntry != NULL && rEntry->isValid) {
            PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
            if (nEntry != NULL && nEntry->isValid) {
                if (nEntry->neighFlag) {
                    //forwarding TU-RREP
                    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forwarding UU-RREP as TU-RREP\n");
                    PASER_TU_RREP *packet = packet_sender->forward_uu_rrep_to_tu_rrep(uurrep_msg, rEntry->nxthop_addr);
                    delete packet;
                } else {
                    //forwarding UU-RREP
                    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forwarding UU-RREP as UU-RREP\n");
                    PASER_UU_RREP *packet = packet_sender->forward_uu_rrep(uurrep_msg, rEntry->nxthop_addr);
                    if (packet == NULL) {
                        delete uurrep_msg;
                        return;
                    }
                    PASER_routing_entry *rEntry = routing_table->findDest(packet->srcAddress_var);
                    packet_rreq_entry *rrep = rrep_list->pending_find(rEntry->nxthop_addr);
                    if (rrep) {
                        timer_queue->timer_remove(rrep->tPack);
                        delete rrep->tPack;
                    } else {
                        rrep = rrep_list->pending_add(rEntry->nxthop_addr);
                    }
                    rrep->tries = 0;

                    PASER_timer_packet *tPack = new PASER_timer_packet();
                    tPack->data = (void *) packet;
                    tPack->destAddr.s_addr = rEntry->nxthop_addr.s_addr;
                    tPack->handler = TU_RREP_ACK_TIMEOUT;
                    tPack->timeout = timeval_add(now, PASER_UU_RREP_WAIT_TIME);

                    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Set TU_RREP_ACK_TIMEOUT timeout: sec: %ld, usec: %ld\n",
                            tPack->timeout.tv_sec, tPack->timeout.tv_usec);
                    timer_queue->timer_add(tPack);
                    rrep->tPack = tPack;
                }
            } else {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING,
                        "handleUURREP Error: Could not find the destination node(Route not exist)!\n");
                std::list<unreachableBlock> allAddrList;
                unreachableBlock temp;
                temp.addr.s_addr = uurrep_msg->srcAddress_var.s_addr;
                temp.seq = 0;
                allAddrList.push_back(temp);
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send RERR\n");
                packet_sender->send_rerr(allAddrList);
                delete uurrep_msg;
                return;
            }
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING,
                    "handleUURREP Error: Could not find the destination node(NextHop not exist)!\n");
            std::list<unreachableBlock> allAddrList;
            unreachableBlock temp;
            temp.addr.s_addr = uurrep_msg->srcAddress_var.s_addr;
            temp.seq = 0;
            allAddrList.push_back(temp);
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send RERR\n");
            packet_sender->send_rerr(allAddrList);
            delete uurrep_msg;
            return;
        }
    } else {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "I am a destination\n");
    }
    delete uurrep_msg;
}

void PASER_packet_processing::handleTURREQ(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_TU_RREQ *turreq_msg = dynamic_cast<PASER_TU_RREQ *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete turreq_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", turreq_msg->detailedInfo().c_str());

    //pruefe keyNr
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check GTK number...");
    if (turreq_msg->keyNr != pGlobal->getKeyNr()) {
        packet_sender->send_reset();
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\nSend RESET.\n");
        delete turreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    if (checkRouteList(turreq_msg->AddressRangeList)) {
        delete turreq_msg;
        return;
    }

    struct in_addr forwarding = turreq_msg->AddressRangeList.back().ipaddr;
    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), forwarding)) {
        delete turreq_msg;
        return;
    }
    if (!check_geo(turreq_msg->geoForwarding)) {
        delete turreq_msg;
        return;
    }

    PASER_neighbor_entry *neigh = neighbor_table->findNeigh(forwarding);
    if (!neigh || !neigh->neighFlag) {
        if (!neigh) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find neighbor entry.\n");
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Neighbor is not trusted.\n");
        }
        delete turreq_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash.\n");
    if (!crypto_hash->checkHmacTURREQ(turreq_msg, pGlobal->getGTK())) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...FALSE\n");
        delete turreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...OK\n");

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element.\n");
    u_int32_t newIV = 0;
    if (!root->checkRoot(neigh->root, turreq_msg->secret, turreq_msg->auth, neigh->IV, &newIV)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...FALSE\n");
        delete turreq_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...OK\n");

    neighbor_table->updateNeighborTableIVandSetValid(neigh->neighbor_addr, newIV);

    struct timeval now;
    pGlobal->getPASERtimeofday(&now);

    //update Neighbor Table
    neighbor_table->updateNeighborTableTimeout(forwarding, now);

    //update Routing Table with forwarding Node
    routing_table->updateRoutingTableTimeout(forwarding, turreq_msg->seqForw, now);

    //update Routing Table
//    std::list<address_range> EmptyAddList;
    X509 *cert = NULL;
    if (turreq_msg->GFlag) {
        cert = crypto_sign->extractCert(turreq_msg->cert);
        if (cert != NULL && crypto_sign->checkOneCert(cert) == 0) {
            X509_free(cert);
            delete turreq_msg;
            return;
        }
    }
    routing_table->updateRoutingTableAndSetTableTimeout(turreq_msg->AddressRangeList.front().range, turreq_msg->srcAddress_var,
            turreq_msg->seq, cert, forwarding, turreq_msg->metricBetweenQueryingAndForw, ifIndex, now, crypto_sign->isGwCert(cert), true);

    PASER_routing_entry *rEntry = routing_table->findDest(turreq_msg->srcAddress_var);
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
    if (nEntry && nEntry->neighFlag && nEntry->isValid) {
        routing_table->updateRoutingTable(now, turreq_msg->AddressRangeList, forwarding, ifIndex);
    }
    // send queued Packets
    if (nEntry && nEntry->neighFlag) {
        // send packets
        deleteRouteRequestTimeout(turreq_msg->srcAddress_var);
        struct in_addr netmask;
        netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        pGlobal->getPASER_socket()->releaseQueue(turreq_msg->srcAddress_var, netmask);
//        packet_queue->send_queued_packets(turreq_msg->srcAddress_var);
        deleteRouteRequestTimeoutForAddList(turreq_msg->AddressRangeList);
        pGlobal->getPASER_socket()->releaseQueue_for_AddList(turreq_msg->AddressRangeList);
//        packet_queue->send_queued_packets_for_AddList(turreq_msg->AddressRangeList);
    }

    if (paser_configuration->isAddInMyLocalAddress(turreq_msg->destAddress_var) || pGlobal->getPaser_configuration()->getIsGW()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "I am a destination\n");
        if (turreq_msg->GFlag) {
            cert = crypto_sign->extractCert(turreq_msg->cert);
            if (paser_configuration->getIsGW()) {
                //sende anfrage an KDC
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forward request to KDC. Generate GTK Request.\n");
                packet_sender->sendKDCRequest(turreq_msg->srcAddress_var, forwarding, turreq_msg->cert, turreq_msg->nonce);
                X509_free(cert);
                delete turreq_msg;
                return;
            }
        }
        in_addr WlanAddrStruct;
        PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(forwarding);
        int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
        WlanAddrStruct.s_addr = netDevice[ifId].ipaddr.s_addr;
        kdc_block tempKdcBlock;
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Generate and send TU-RREP.\n");
        PASER_TU_RREP *packet = packet_sender->send_tu_rrep(turreq_msg->srcAddress_var, forwarding, WlanAddrStruct/*myAddrStruct*/,
                turreq_msg->GFlag, cert, tempKdcBlock);
        if (turreq_msg->GFlag) {
            X509_free(cert);
        }
        delete packet;
    }
    // forwarding TURREQ
    else {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forwarding TU-RREQ as TU-RREQ.\n");
        PASER_routing_entry *rEntry = routing_table->findDest(turreq_msg->destAddress_var);
        if (rEntry == NULL || !rEntry->isValid) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "handleUURREP Error: Could not find the destination node(Route not exist)!\n");
            std::list<unreachableBlock> allAddrList;
            unreachableBlock temp;
            temp.addr.s_addr = turreq_msg->destAddress_var.s_addr;
            temp.seq = 0;
            allAddrList.push_back(temp);
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send RERR\n");
            packet_sender->send_rerr(allAddrList);
            delete turreq_msg;
            return;
        }
        PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
        if (nEntry == NULL || !nEntry->neighFlag || !nEntry->isValid) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING,
                    "handleUURREP Error: Could not find the destination node(NextHop not exist)!\n");
            std::list<unreachableBlock> allAddrList;
            unreachableBlock temp;
            temp.addr.s_addr = turreq_msg->destAddress_var.s_addr;
            temp.seq = 0;
            allAddrList.push_back(temp);
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send RERR\n");
            packet_sender->send_rerr(allAddrList);
            delete turreq_msg;
            return;
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Generate and send TU-RREQ.\n");
            PASER_TU_RREQ *packet = packet_sender->forward_tu_rreq(turreq_msg, rEntry->nxthop_addr);
            delete packet;
            delete turreq_msg;
            return;
        }
    }
    delete turreq_msg;
}

void PASER_packet_processing::handleTURREP(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_TU_RREP *turrep_msg = dynamic_cast<PASER_TU_RREP *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete turrep_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", turrep_msg->detailedInfo().c_str());

    //pruefe keyNr
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check GTK number...");
    if (turrep_msg->keyNr != pGlobal->getKeyNr()) {
        packet_sender->send_reset();
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\nsend RESET\n");
        delete turrep_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    if (checkRouteList(turrep_msg->AddressRangeList)) {
        delete turrep_msg;
        return;
    }

    struct in_addr forwarding = turrep_msg->AddressRangeList.back().ipaddr;
    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), forwarding)) {
        delete turrep_msg;
        return;
    }
    if (!check_geo(turrep_msg->geoForwarding)) {
        delete turrep_msg;
        return;
    }

    PASER_neighbor_entry *neigh = neighbor_table->findNeigh(forwarding);
    if (!neigh || !neigh->neighFlag) {
        if (!neigh) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find neighbor entry.\n");
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Neighbor is not trusted.\n");
        }
        delete turrep_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash.\n");
    if (!crypto_hash->checkHmacTURREP(turrep_msg, pGlobal->getGTK())) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...FALSE\n");
        delete turrep_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...OK\n");

    // read KDC
    if (turrep_msg->GFlag && paser_configuration->isAddInMyLocalAddress(turrep_msg->srcAddress_var)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Nonce...");
        if (pGlobal->getLastGwSearchNonce() != turrep_msg->kdc_data.nonce) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE.\n");
            delete turrep_msg;
            return;
        }
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "OK.\n");

        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check KDC Signature.\n");
        if (crypto_sign->checkSignKDC(turrep_msg->kdc_data) != 1) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check KDC Signature...FALSE\n");
            delete turrep_msg;
            return;
        }
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check KDC Signature...OK\n");

        //da GTK.buf ein Zeiger auf paser_config->gtk.buf ist, wird es auch in paser_config freigegeben
        lv_block gtk;
        gtk.len = 0;
        gtk.buf = NULL;
        crypto_sign->rsa_dencrypt(turrep_msg->kdc_data.GTK, &gtk);
        pGlobal->setGTK(gtk);
        if (gtk.len > 0) {
            free(gtk.buf);
        }
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element.\n");
    u_int32_t newIV = 0;
    if (!root->checkRoot(neigh->root, turrep_msg->secret, turrep_msg->auth, neigh->IV, &newIV)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...FALSE\n");
        delete turrep_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...OK\n");

    neighbor_table->updateNeighborTableIVandSetValid(neigh->neighbor_addr, newIV);

    struct timeval now;
    pGlobal->getPASERtimeofday(&now);

    //update Neighbor Table
    neighbor_table->updateNeighborTableTimeout(forwarding, now);
    //update Routing Table with forwarding Node
    routing_table->updateRoutingTableTimeout(forwarding, now, ifIndex);
    //update Routing Table
    routing_table->updateRoutingTableAndSetTableTimeout(turrep_msg->AddressRangeList.front().range, turrep_msg->destAddress_var,
            turrep_msg->seq, NULL, forwarding, turrep_msg->metricBetweenDestAndForw, ifIndex, now,
            turrep_msg->GFlag || turrep_msg->searchGW, true);

    if (turrep_msg->GFlag) {
        pGlobal->setIsRegistered(true);
        pGlobal->setWasRegistered(true);
    }

    // delete TIMEOUT
    if (turrep_msg->GFlag == 0x01) {
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0xFFFFFFFF;
        deleteRouteRequestTimeout(bcast_addr);
    }
    if (turrep_msg->searchGW == 0x01) {
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0x00000000;
        deleteRouteRequestTimeout(bcast_addr);
    }

    PASER_routing_entry *rEntry = routing_table->findDest(turrep_msg->destAddress_var);
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntry->nxthop_addr);
    if (nEntry && nEntry->neighFlag && nEntry->isValid) {
        routing_table->updateRoutingTable(now, turrep_msg->AddressRangeList, forwarding, ifIndex);
    }

    // send queued Packets
    if (nEntry && nEntry->neighFlag) {
        // send packets
        if (turrep_msg->searchGW == 0x01) {
            struct in_addr bcast_addr;
            bcast_addr.s_addr = (in_addr_t) 0x00000000;
            pGlobal->getPASER_socket()->releaseQueue(bcast_addr, bcast_addr);
        }
        struct in_addr nodemask;
        nodemask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        deleteRouteRequestTimeout(turrep_msg->destAddress_var);
        pGlobal->getPASER_socket()->releaseQueue(turrep_msg->destAddress_var, nodemask);
//        packet_queue->send_queued_packets(turrep_msg->destAddress_var);
        deleteRouteRequestTimeoutForAddList(turrep_msg->AddressRangeList);
        pGlobal->getPASER_socket()->releaseQueue_for_AddList(turrep_msg->AddressRangeList);
//        packet_queue->send_queued_packets_for_AddList(turrep_msg->AddressRangeList);
    }

    // i am a querying Node
    if (paser_configuration->isAddInMyLocalAddress(turrep_msg->srcAddress_var)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "I am a destination\n");
        // delete TIMEOUT
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0xFFFFFFFF;
        packet_rreq_entry *rreq_bc = rreq_list->pending_find(bcast_addr);
        if (rreq_bc && turrep_msg->GFlag == 0x01) {
            rreq_list->pending_remove(rreq_bc);
            PASER_timer_packet *timeout = rreq_bc->tPack;
            timer_queue->timer_remove(timeout);
            delete timeout;
            delete rreq_bc;
        }
        packet_rreq_entry *rreq = rreq_list->pending_find(turrep_msg->destAddress_var);
        if (rreq) {
            rreq_list->pending_remove(rreq);
            PASER_timer_packet *timeout = rreq->tPack;
            timer_queue->timer_remove(timeout);
            delete timeout;
            delete rreq;
        }
        // send packets
        struct in_addr nodemask;
        nodemask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        pGlobal->getPASER_socket()->releaseQueue(turrep_msg->destAddress_var, nodemask);
//        packet_queue->send_queued_packets(turrep_msg->destAddress_var);
    } else {
        // Forwarding
        PASER_routing_entry *rout = routing_table->findDest(turrep_msg->srcAddress_var);
        PASER_neighbor_entry *neigh = NULL;
        if (rout != NULL) {
            neigh = neighbor_table->findNeigh(rout->nxthop_addr);
        }
        if (rout == NULL || neigh == NULL) {
            //ERROR
            delete turrep_msg;
            return;
        }
        // forwarding TURREP to UURREP
        if (neigh->neighFlag == 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forwarding TU-RREP as UU-RREP\n");
            PASER_UU_RREP *packet = packet_sender->forward_tu_rrep_to_uu_rrep(turrep_msg, neigh->neighbor_addr);
            // set TU-RREP-ACK Timeout
            packet_rreq_entry *rrep = rrep_list->pending_find(neigh->neighbor_addr);
            if (rrep) {
                timer_queue->timer_remove(rrep->tPack);
                delete rrep->tPack;
            } else {
                rrep = rrep_list->pending_add(neigh->neighbor_addr);
            }
            rrep->tries = 0;

            PASER_timer_packet *tPack = new PASER_timer_packet();
            tPack->data = (void *) packet;
            tPack->destAddr.s_addr = neigh->neighbor_addr.s_addr;
            tPack->handler = TU_RREP_ACK_TIMEOUT;
            tPack->timeout = timeval_add(now, PASER_UU_RREP_WAIT_TIME);

            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Set TU_RREP_ACK_TIMEOUT timeout: sec: %ld, usec: %ld\n",
                    tPack->timeout.tv_sec, tPack->timeout.tv_usec);
//            ev<< "now: " << now.tv_sec << "\ntimeout: " << tPack->timeout.tv_sec << "\n";
            timer_queue->timer_add(tPack);
            rrep->tPack = tPack;
        }
        // forwarding TURREP
        else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forwarding TU-RREP as TU-RREP\n");
            PASER_routing_entry *rEntry = routing_table->findDest(turrep_msg->srcAddress_var);
            if (rEntry == NULL) {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find Route to Destination\n");
            } else {
                PASER_TU_RREP *packet = packet_sender->forward_tu_rrep(turrep_msg, rEntry->nxthop_addr);
                delete packet;
            }
        }
    }
    delete turrep_msg;
}

void PASER_packet_processing::handleTURREPACK(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_TU_RREP_ACK *turrepack_msg = dynamic_cast<PASER_TU_RREP_ACK *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete turrepack_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", turrepack_msg->detailedInfo().c_str());

    //pruefe keyNr
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check GTK number...");
    if (turrepack_msg->keyNr != pGlobal->getKeyNr()) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\nSend RESET.\n");
        packet_sender->send_reset();
        delete turrepack_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    struct in_addr neighbor = turrepack_msg->srcAddress_var;
    PASER_neighbor_entry *neigh = neighbor_table->findNeigh(neighbor);
    if (!neigh) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find neighbor entry.");
        delete turrepack_msg;
        return;
    }

    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), neighbor)) {
        delete turrepack_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash.\n");
    if (!crypto_hash->checkHmacTURREPACK(turrepack_msg, pGlobal->getGTK())) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...FALSE\n");
        delete turrepack_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...OK\n");

    u_int32_t newIV = 0;
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element.\n");
    if (!root->checkRoot(neigh->root, turrepack_msg->secret, turrepack_msg->auth, neigh->IV, &newIV)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...FALSE\n");
        delete turrepack_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...OK\n");

    neighbor_table->updateNeighborTableIVandSetValid(neigh->neighbor_addr, newIV);

    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    //update Routing Table with forwarding Node
    PASER_routing_entry *rEntry = routing_table->findDest(neighbor);
    if (!rEntry) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find route to the neighbor.\n");
        delete turrepack_msg;
        return;
    }
    rEntry->nxthop_addr.s_addr = neighbor.s_addr;
    rEntry->hopcnt = 1;

    routing_table->updateRoutingTableTimeout(neighbor, turrepack_msg->seq, now);
    //update neighbor table
    neighbor_table->updateNeighborTableTimeout(neighbor, now);
    neigh->neighFlag = 1;
    //OMNET: Kernel Routing Table
    struct in_addr netmask;
    netmask.s_addr = PASER_ALLONES_ADDRESS_MASK;
    if (true) {
//        routing_table->updateKernelRoutingTable(neighbor, neighbor, netmask, 1, true, ifIndex);
        routing_table->updateKernelRoutingTable(neighbor, neighbor, netmask, 1, false, ifIndex);
    }

    // send queued Packets
    PASER_routing_entry *rEntryTemp = routing_table->findDest(turrepack_msg->srcAddress_var);
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(rEntryTemp->nxthop_addr);
    if (nEntry && nEntry->neighFlag && nEntry->isValid) {
        deleteRouteRequestTimeout(turrepack_msg->srcAddress_var);
        // send packets
        struct in_addr nodemask;
        nodemask.s_addr = PASER_ALLONES_ADDRESS_MASK;
        pGlobal->getPASER_socket()->releaseQueue(turrepack_msg->srcAddress_var, nodemask);
//        packet_queue->send_queued_packets(turrepack_msg->srcAddress_var);
        std::list<PASER_routing_entry*> entryList = routing_table->getListWithNextHop(turrepack_msg->srcAddress_var);
        std::list<address_list> addList;
        for (std::list<PASER_routing_entry*>::iterator it = entryList.begin(); it != entryList.end(); it++) {
            address_list tempAddList;
            PASER_routing_entry *tempRoutingEntry = (PASER_routing_entry*) *it;
            tempAddList.ipaddr = tempRoutingEntry->dest_addr;
            tempAddList.range = tempRoutingEntry->AddL;
        }

        deleteRouteRequestTimeoutForAddList(addList);
        // send packets
        pGlobal->getPASER_socket()->releaseQueue_for_AddList(addList);
//        packet_queue->send_queued_packets_for_AddList(addList);
    }

    packet_rreq_entry * rrep = rrep_list->pending_find(turrepack_msg->srcAddress_var);
    if (rrep) {
        PASER_timer_packet *tPack = rrep->tPack;
        rrep_list->pending_remove(rrep);
        timer_queue->timer_remove(tPack);
        delete tPack;
        delete rrep;
    }
    delete turrepack_msg;
}

void PASER_packet_processing::handleRERR(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_TB_RERR *rerr_msg = dynamic_cast<PASER_TB_RERR *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete rerr_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", rerr_msg->detailedInfo().c_str());

    //pruefe keyNr
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check GTK number...");
    if (rerr_msg->keyNr != pGlobal->getKeyNr()) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\nSend RESET.\n");
        packet_sender->send_reset();
        delete rerr_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    struct in_addr neighbor = rerr_msg->srcAddress_var;
    PASER_neighbor_entry *neigh = neighbor_table->findNeigh(neighbor);
    if (!neigh) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find neighbor entry.\n");
        delete rerr_msg;
        return;
    }

    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), neighbor)) {
        delete rerr_msg;
        return;
    }

    //check HASH
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash.\n");
    if (!crypto_hash->checkHmacRERR(rerr_msg, pGlobal->getGTK())) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...FALSE\n");
        delete rerr_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...OK\n");

    //check root
    u_int32_t newIV = 0;
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element.\n");
    if (!root->checkRoot(neigh->root, rerr_msg->secret, rerr_msg->auth, neigh->IV, &newIV)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...FALSE\n");
        delete rerr_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...OK\n");

    neighbor_table->updateNeighborTableIV(neigh->neighbor_addr, newIV);

    std::list<unreachableBlock> forwardingList;
    //check each SeqNr
    for (std::list<unreachableBlock>::iterator it = rerr_msg->UnreachableAdressesList.begin();
            it != rerr_msg->UnreachableAdressesList.end(); it++) {
        unreachableBlock temp = (unreachableBlock) *it;
        PASER_routing_entry *tempEntry = routing_table->findDest(temp.addr);
        if (tempEntry == NULL || neighbor.s_addr != tempEntry->nxthop_addr.s_addr || !tempEntry->isValid) {
            continue;
        }
//        if(temp.seq < tempEntry->seqnum && temp.seq!=0){
        if (pGlobal->isSeqNew(tempEntry->seqnum, temp.seq) && temp.seq != 0) {
            continue;
        }
        //loesche Route
        for (std::list<address_range>::iterator it2 = tempEntry->AddL.begin(); it2 != tempEntry->AddL.end(); it2++) {
            address_range addList = (address_range) *it2;
            routing_table->updateKernelRoutingTable(addList.ipaddr, tempEntry->nxthop_addr, addList.mask, tempEntry->hopcnt + 1, true, 1);
        }
        in_addr tempMask;
        tempMask.s_addr = (in_addr_t) 0xFFFFFFFF;
        routing_table->updateKernelRoutingTable(tempEntry->dest_addr, tempEntry->nxthop_addr, tempMask, tempEntry->hopcnt, true, 1);
        PASER_timer_packet *validTimer = tempEntry->validTimer;
        if (validTimer) {
            timer_queue->timer_remove(validTimer);
            delete validTimer;
            tempEntry->validTimer = NULL;
        }
        tempEntry->isValid = 0;
        if (temp.seq != 0) {
            tempEntry->seqnum = temp.seq;
        }
        unreachableBlock newEntry;
        newEntry.addr.s_addr = temp.addr.s_addr;
        newEntry.seq = temp.seq;
        forwardingList.push_back(newEntry);
    }

    //generate and send RERR
    if (forwardingList.size() > 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forwarding RERR.\n");
        packet_sender->send_rerr(forwardingList);
    } else {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Don't need RERR to forward.\n");
    }

    delete rerr_msg;
}

void PASER_packet_processing::handleHELLO(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_TB_HELLO *hello_msg = dynamic_cast<PASER_TB_HELLO *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete hello_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", hello_msg->detailedInfo().c_str());

    if (pGlobal->getPaser_configuration()->isAddInMyLocalAddress(hello_msg->srcAddress_var)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Loop back.\n");
        delete hello_msg;
        return;
    }

    struct in_addr neighbor = hello_msg->srcAddress_var;
    PASER_neighbor_entry *neigh = neighbor_table->findNeigh(neighbor);
    if (!neigh || !neigh->neighFlag) {
        if (!neigh) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find neighbor entry.\n");
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Neighbor is not trusted.\n");
        }
        delete hello_msg;
        return;
    }

    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), neighbor)) {
        delete hello_msg;
        return;
    }

    //check HASH
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash.\n");
    if (!crypto_hash->checkHmacHELLO(hello_msg, pGlobal->getGTK())) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...FALSE\n");
        delete hello_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Hash...OK\n");

    //check root
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element.\n");
    u_int32_t newIV = 0;
    if (!root->checkRoot(neigh->root, hello_msg->secret, hello_msg->auth, neigh->IV, &newIV)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...FALSE\n");
        delete hello_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check root element...OK\n");

    bool found = false;
    for (std::list<address_list>::iterator it = hello_msg->AddressRangeList.begin(); it != hello_msg->AddressRangeList.end(); it++) {
        address_list tempMe = (address_list) *it;
        if (paser_configuration->isAddInMyLocalAddress(tempMe.ipaddr)) {
            found = true;
            break;
        }
    }
    if (!found) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "The neighbor does not trust me..\n");
        delete hello_msg;
        return;
    }
    neighbor_table->updateNeighborTableIVandSetValid(neigh->neighbor_addr, newIV);

    //update all routes and neighbors
    for (std::list<address_list>::iterator it = hello_msg->AddressRangeList.begin(); it != hello_msg->AddressRangeList.end(); it++) {
        address_list tempList = (address_list) *it;
        if (paser_configuration->isAddInMyLocalAddress(tempList.ipaddr)) {
            continue;
        }
        if (tempList.ipaddr.s_addr == neighbor.s_addr) {
            routing_table->updateNeighborFromHELLO(tempList, hello_msg->seq, ifIndex);
        } else {
            routing_table->updateRouteFromHELLO(tempList, ifIndex, neighbor);
        }
    }
    delete hello_msg;
}

void PASER_packet_processing::handleB_ROOT(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_B_ROOT *b_root_msg = dynamic_cast<PASER_B_ROOT *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete b_root_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", b_root_msg->detailedInfo().c_str());

    struct in_addr querying = b_root_msg->srcAddress_var;
    //Pruefe Sequenznummer des Pakets
    if (!check_seq_nr((dynamic_cast<PASER_MSG *>(msg)), querying)) {
        delete b_root_msg;
        return;
    }

    //Pruefe GeoPosition des Absenders
    if (!check_geo(b_root_msg->geoQuerying)) {
        delete b_root_msg;
        return;
    }

    //pruefe Timestamp
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Timestamp...");
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    if (now.tv_sec - b_root_msg->timestamp > PASER_time_diff || now.tv_sec - b_root_msg->timestamp < -PASER_time_diff) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\n");
        delete b_root_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    //Pruefe Signatur des Pakets
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature.\n");
    if (!crypto_sign->checkSignB_ROOT(b_root_msg)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...FALSE\n");
        delete b_root_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...OK\n");

    //speichere neues ROOT und IV
    PASER_routing_entry *rEntry = routing_table->findDest(querying);
    if (rEntry == NULL || rEntry->hopcnt != 1) {
        if (rEntry == NULL) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find route to the node.\n");
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "The node is not my neighbor.\n");
        }
        delete b_root_msg;
        return;
    }
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(querying);
    if (nEntry == NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find neighbor entry.\n");
        delete b_root_msg;
        return;
    }
    rEntry->seqnum = b_root_msg->seq;

    free(nEntry->root);
    u_int8_t *rootN = (u_int8_t *) malloc((sizeof(u_int8_t) * SHA256_DIGEST_LENGTH));
    memcpy(rootN, b_root_msg->root, (sizeof(u_int8_t) * SHA256_DIGEST_LENGTH));
    nEntry->root = rootN;
    nEntry->IV = b_root_msg->initVector;
//printf("e_root:0x");
//for (int n = 0; n < SHA256_DIGEST_LENGTH; n++)
//    printf("%02x", rootN[n]);
//putchar('\n');
    delete b_root_msg;
}

void PASER_packet_processing::handleB_RESET(PASER_MSG * msg, u_int32_t ifIndex) {
    PASER_RESET *b_reset_msg = dynamic_cast<PASER_RESET *>(msg);
    if (!pGlobal->getWasRegistered()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Not registered.\n");
        delete b_reset_msg;
        return;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", b_reset_msg->detailedInfo().c_str());

    //pruefe keyNr
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check GTK number...");
    if (b_reset_msg->keyNr < pGlobal->getKeyNr()) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "FALSE\nSend RESET.\n");
        packet_sender->send_reset();
        delete b_reset_msg;
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_PACKET_PROCESSING, "OK\n");

    //pruefe Schluesselnummer
    u_int32_t myKeyNr = pGlobal->getKeyNr();
    if (myKeyNr >= b_reset_msg->keyNr) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "GTK number is actual. Do nothing.\n");
        delete b_reset_msg;
        return;
    }

    //Pruefe ob Zertifikat ein KDC Zertifikat ist
    X509* certFromKDC = crypto_sign->extractCert(b_reset_msg->cert);
    if (!crypto_sign->isKdcCert(certFromKDC)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Certificate of the RESET packet is not a KDC certificate.\n");
        X509_free(certFromKDC);
        delete b_reset_msg;
        return;
    }
    X509_free(certFromKDC);

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature.\n");
    //Pruefe Signatur des Schluesselsnummer
    if (!crypto_sign->checkSignRESET(b_reset_msg)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...FALSE\n");
        delete b_reset_msg;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...OK\n");

    pGlobal->setKeyNr(b_reset_msg->keyNr);
    pGlobal->resetPASER();

    //speichere neuen Zertifikat und Signatur von RESET
    pGlobal->setKDC_cert(b_reset_msg->cert);
    pGlobal->setRESET_sign(b_reset_msg->sign);
//printf("sign_from__RESET_:");
//for (int n = 0; n < b_reset_msg->sign.len; n++)
//    printf("%02x", b_reset_msg->sign.buf[n]);
//putchar('\n');

    //leite RESET nachricht weiter
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forward RESER packet.\n");
    packet_sender->send_reset();
//return;

    //Registriere sich neu
    if (paser_configuration->getIsGW()) {
        lv_block cert;
        if (!crypto_sign->getCert(&cert)) {
//            ev<< "cert ERROR\n";
            delete b_reset_msg;
            return;
        }
        pGlobal->generateGwSearchNonce();
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "I am a gateway. Generate and send KDC request.\n");
        packet_sender->sendKDCRequest(paser_configuration->getNetDevice()[0].ipaddr, paser_configuration->getNetDevice()[0].ipaddr, cert,
                pGlobal->getLastGwSearchNonce());
//return;
        free(cert.buf);

        PASER_timer_packet *timePacket = new PASER_timer_packet();
        struct timeval now;
        pGlobal->getPASERtimeofday(&now);
        timePacket->handler = KDC_REQUEST;
//        timePacket->timeout = timeval_add(now, paser_modul->par("KDCWaitTime").doubleValue()/(double)1000);
        timePacket->timeout = timeval_add(now, PASER_KDC_REQUEST_TIME);
        timePacket->destAddr = paser_configuration->getAddressOfKDC();
        timer_queue->timer_add(timePacket);
    } else {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Start registration.\n");
        route_findung->tryToRegister();
    }

    delete b_reset_msg;
}

void PASER_packet_processing::deleteRouteRequestTimeout(struct in_addr dest_addr) {
    packet_rreq_entry *rreq = rreq_list->pending_find(dest_addr);
    if (rreq) {
        rreq_list->pending_remove(rreq);
        PASER_timer_packet *timeout = rreq->tPack;
        timer_queue->timer_remove(timeout);
        delete timeout;
        delete rreq;
    }
}

void PASER_packet_processing::deleteRouteRequestTimeoutForAddList(std::list<address_list> AddList) {
    packet_rreq_entry *rreq;
    for (std::list<address_list>::iterator it = AddList.begin(); it != AddList.end(); it++) {
        address_list tempList = (address_list) *it;
        for (std::list<address_range>::iterator it2 = tempList.range.begin(); it2 != tempList.range.end(); it2++) {
            address_range tempRange = (address_range) *it2;
            rreq = rreq_list->pending_find_addr_with_mask(tempRange.ipaddr, tempRange.mask);
            if (rreq) {
                rreq_list->pending_remove(rreq);
                PASER_timer_packet *timeout = rreq->tPack;
                timer_queue->timer_remove(timeout);
                delete timeout;
                delete rreq;
            }
        }
    }
}

void PASER_packet_processing::handleKDCReply(PASER_MSG *msg) {

    PASER_GTKREP *kdc_resp = dynamic_cast<PASER_GTKREP *>(msg);

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Incoming Packet Info\n%s", kdc_resp->detailedInfo().c_str());

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature.\n");
    if (!crypto_sign->checkSignGTKResponse(kdc_resp)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...FALSE\n");
        delete kdc_resp;
        return;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature...OK\n");

    //convert PacketData to KdcData
    kdc_block kdcData;
    kdcData.CRL = kdc_resp->crl;
    kdcData.GTK = kdc_resp->gtk;
    kdcData.cert_kdc = kdc_resp->kdc_cert;
    kdcData.key_nr = kdc_resp->kdc_key_nr;
    kdcData.nonce = kdc_resp->nonce;
    kdcData.sign = kdc_resp->sign_kdc_block;
    kdcData.sign_key = kdc_resp->sign_key;

    if (paser_configuration->isAddInMyLocalAddress(kdc_resp->srcAddress_var)) {

        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature and request nonce of kdc block.\n");
        if (crypto_sign->checkSignKDC(kdcData) == 1 && kdcData.nonce == pGlobal->getLastGwSearchNonce()) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature and request nonce  of kdc block...OK\n");
            //KDC OK
            pGlobal->getNeighbor_table()->checkAllCert();
            pGlobal->setIsRegistered(true);
            pGlobal->setWasRegistered(true);
            lv_block gtk;
            gtk.len = 0;
            gtk.buf = NULL;
            crypto_sign->rsa_dencrypt(kdcData.GTK, &gtk);
            pGlobal->setGTK(gtk);
            pGlobal->setKeyNr(kdcData.key_nr);
            if (gtk.len > 0) {
                free(gtk.buf);
            }
            PASER_timer_packet *timePack = new PASER_timer_packet();
            timePack->handler = KDC_REQUEST;
            timer_queue->timer_remove(timePack);
            delete timePack;
            delete kdc_resp;
            return;
        } else {
            if (kdcData.nonce != pGlobal->getLastGwSearchNonce()) {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "FALSE nonce\n");
            }
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Check Signature and request nonce  of kdc block...FALSE\n");
            //Fehler, sende KDC Request nochmal
            delete kdc_resp;
            return;
        }
    } else {
        //send replay
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Forward KDC reply.\n");
        struct in_addr nextHopAddr = kdc_resp->nextHopAddr;
        struct in_addr srcAddr = kdc_resp->srcAddress_var;

        PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nextHopAddr);
        if (nEntry == NULL) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find next hop node\n");
            delete kdc_resp;
            return;
        }

        struct in_addr WlanAddrStruct;
        int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
        WlanAddrStruct.s_addr = netDevice[ifId].ipaddr.s_addr;
        if (!nEntry->neighFlag) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send UU-RREP.\n");
            PASER_UU_RREP *packet = packet_sender->send_uu_rrep(srcAddr, nEntry->neighbor_addr, WlanAddrStruct, true, NULL, kdcData);
            if (packet == NULL) {
                delete kdc_resp;
                return;
            }
            packet_rreq_entry *rrep = rrep_list->pending_find(nEntry->neighbor_addr);
            if (rrep) {
                timer_queue->timer_remove(rrep->tPack);
                delete rrep->tPack;
            } else {
                rrep = rrep_list->pending_add(nEntry->neighbor_addr);
            }
            rrep->tries = 0;
            struct timeval now;
            pGlobal->getPASERtimeofday(&now);
            PASER_timer_packet *tPack = new PASER_timer_packet();
            tPack->data = (void *) packet;
            tPack->destAddr.s_addr = nEntry->neighbor_addr.s_addr;
            tPack->handler = TU_RREP_ACK_TIMEOUT;
            tPack->timeout = timeval_add(now, PASER_UU_RREP_WAIT_TIME);

            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Set TU_RREP_ACK_TIMEOUT. Sec: %d, usec: %d\n",
                    (int)tPack->timeout.tv_sec, (int)tPack->timeout.tv_usec);
            timer_queue->timer_add(tPack);
            rrep->tPack = tPack;
        } else {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send TU-RREP.\n");
            PASER_TU_RREP *packet = packet_sender->send_tu_rrep(srcAddr, nEntry->neighbor_addr, WlanAddrStruct, true, NULL, kdcData);
            if (packet == NULL) {
                delete kdc_resp;
                return;
            }
            delete packet;
        }

    }
    delete kdc_resp;
}

