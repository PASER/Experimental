/**
 *\class  		PASER_packet_sender
 *@brief       	Class provides functions for working with all PASER messages (sender)
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

#include "PASER_packet_sender.h"

PASER_packet_sender::PASER_packet_sender(PASER_global* paser_global) {
    pGlobal = paser_global;
    paser_configuration = NULL;
    root = NULL;
    crypto_sign = NULL;
    crypto_hash = NULL;
    routing_table = NULL;
    neighbor_table = NULL;
}

PASER_packet_sender::~PASER_packet_sender() {

}

void PASER_packet_sender::init() {
    paser_configuration = pGlobal->getPaser_configuration();

    root = pGlobal->getRoot();
    crypto_sign = pGlobal->getCrypto_sign();
    crypto_hash = pGlobal->getCrypto_hash();
    routing_table = pGlobal->getRouting_table();
    neighbor_table = pGlobal->getNeighbor_table();
}

PASER_UB_RREQ * PASER_packet_sender::send_ub_rreq(struct in_addr src_addr, struct in_addr dest_addr, int isDestGW) {
    if (!pGlobal->getWasRegistered() && !isDestGW && dest_addr.s_addr != PASER_BROADCAST ) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Unregistered => Cann't start route request to %s\n", inet_ntoa(dest_addr));
        return NULL;
    }
    PASER_UB_RREQ *packet = new PASER_UB_RREQ(src_addr, dest_addr, pGlobal->getSeqNr());
    packet->keyNr = pGlobal->getKeyNr();
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    packet->timestamp = now.tv_sec;
    packet->seqForw = pGlobal->getSeqNr();
    packet->GFlag = isDestGW;
    if (isDestGW) {
        //get nonce
        packet->nonce = pGlobal->getLastGwSearchNonce();
    }
    if (!dest_addr.s_addr && !isDestGW) {
        packet->searchGW = 1;
    }
    address_list myAddrList;
    myAddrList.ipaddr = src_addr;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenQueryingAndForw = 0;

    if (isDestGW) {
        lv_block cert;
        if (!crypto_sign->getCert(&cert)) {
            return NULL;
        }
        packet->cert.buf = cert.buf;
        packet->cert.len = cert.len;
    }
    lv_block certForw;
    if (!crypto_sign->getCert(&certForw)) {
        return NULL;
    }
    packet->certForw.buf = certForw.buf;
    packet->certForw.len = certForw.len;
    packet->root = root->getRoot();
    packet->initVector = root->getIV();

    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoQuerying.lat = myGeo.lat;
    packet->geoQuerying.lon = myGeo.lon;
    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    crypto_sign->signUBRREQ(packet);

    // send packet

    struct in_addr bcast_addr;
    bcast_addr.s_addr = PASER_BROADCAST;
    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Send Route Request to Dest: %s, isGW: %d.\n", inet_ntoa(dest_addr), isDestGW);
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "UB-RREQ info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create UB-RREQ.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    int IfId = paser_configuration->getIfIdFromAddress(src_addr);
    if (IfId == -1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find Interface Id for Address: %s.\n", inet_ntoa(src_addr));
        free(packetBuf);
        delete packet;
        return NULL;
    }
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[IfId]));
    if (pGlobal->getPaser_configuration()->isResetHelloByBroadcast()) {
        pGlobal->resetHelloTimer();
    }
    return packet;
}

PASER_UU_RREP * PASER_packet_sender::send_uu_rrep(struct in_addr src_addr, struct in_addr forw_addr, struct in_addr dest_addr, int isDestGW,
        X509 *cert, kdc_block kdcData) {
    PASER_routing_entry * routeEntry = routing_table->findDest(src_addr);
    if (routeEntry == NULL || !routeEntry->isValid) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't send UU-RREP. Route not found.\n");
        return NULL;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Send UU-RREP.\n");
    PASER_UU_RREP *packet = new PASER_UU_RREP(src_addr, dest_addr, pGlobal->getSeqNr());
    packet->keyNr = pGlobal->getKeyNr();
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    packet->timestamp = now.tv_sec;
    if (pGlobal->getPaser_configuration()->getIsGW())
        packet->searchGW = 1;
    else
        packet->searchGW = 0;

    packet->GFlag = isDestGW;

    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(forw_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenQueryingAndForw = routeEntry->hopcnt;
    packet->metricBetweenDestAndForw = 0;

    lv_block certForw;
    if (!crypto_sign->getCert(&certForw)) {
        return NULL;
    }
    packet->certForw.buf = certForw.buf;
    packet->certForw.len = certForw.len;
    packet->root = root->getRoot();
    packet->initVector = root->getIV();

    geo_pos myGeo = pGlobal->getGeoPosition();
    packet->geoDestination.lat = myGeo.lat;
    packet->geoDestination.lon = myGeo.lon;
    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    if (isDestGW) {
        packet->kdc_data.GTK.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.GTK.len));
        memcpy(packet->kdc_data.GTK.buf, kdcData.GTK.buf, (sizeof(u_int8_t) * kdcData.GTK.len));
        packet->kdc_data.GTK.len = kdcData.GTK.len;

        packet->kdc_data.nonce = kdcData.nonce;

        packet->kdc_data.CRL.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.CRL.len));
        memcpy(packet->kdc_data.CRL.buf, kdcData.CRL.buf, (sizeof(u_int8_t) * kdcData.CRL.len));
        packet->kdc_data.CRL.len = kdcData.CRL.len;

        packet->kdc_data.cert_kdc.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.cert_kdc.len));
        memcpy(packet->kdc_data.cert_kdc.buf, kdcData.cert_kdc.buf, (sizeof(u_int8_t) * kdcData.cert_kdc.len));
        packet->kdc_data.cert_kdc.len = kdcData.cert_kdc.len;

        packet->kdc_data.sign.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.sign.len));
        memcpy(packet->kdc_data.sign.buf, kdcData.sign.buf, (sizeof(u_int8_t) * kdcData.sign.len));
        packet->kdc_data.sign.len = kdcData.sign.len;

        packet->kdc_data.key_nr = kdcData.key_nr;

        packet->kdc_data.sign_key.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.sign_key.len));
        memcpy(packet->kdc_data.sign_key.buf, kdcData.sign_key.buf, (sizeof(u_int8_t) * kdcData.sign_key.len));
        packet->kdc_data.sign_key.len = kdcData.sign_key.len;
    } else {
        packet->kdc_data.GTK.buf = NULL;
        packet->kdc_data.GTK.len = 0;
        packet->kdc_data.nonce = 0;
        packet->kdc_data.CRL.buf = NULL;
        packet->kdc_data.CRL.len = 0;
        packet->kdc_data.cert_kdc.buf = NULL;
        packet->kdc_data.cert_kdc.len = 0;
        packet->kdc_data.sign.buf = NULL;
        packet->kdc_data.sign.len = 0;
        packet->kdc_data.key_nr = 0;
        packet->kdc_data.sign_key.buf = NULL;
        packet->kdc_data.sign_key.len = 0;
    }

    crypto_sign->signUURREP(packet);

    // send packet
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "UU-RREP info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create UU-RREP.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, forw_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    pGlobal->incSeqNr();
    return packet;
}

PASER_TU_RREP * PASER_packet_sender::send_tu_rrep(struct in_addr src_addr, struct in_addr forw_addr, struct in_addr dest_addr, int isDestGW,
        X509 *cert, kdc_block kdcData) {
    PASER_routing_entry * routeEntry = routing_table->findDest(src_addr);
    if (routeEntry == NULL || !routeEntry->isValid) {
        return NULL;
    }

    PASER_TU_RREP *packet = new PASER_TU_RREP(src_addr, dest_addr, pGlobal->getSeqNr());
    packet->keyNr = pGlobal->getKeyNr();
    packet->GFlag = isDestGW;

    if (pGlobal->getPaser_configuration()->getIsGW())
        packet->searchGW = 1;
    else
        packet->searchGW = 0;

    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(forw_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenQueryingAndForw = routeEntry->hopcnt;
    packet->metricBetweenDestAndForw = 0;

    if (isDestGW) {
        packet->kdc_data.GTK.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.GTK.len));
        memcpy(packet->kdc_data.GTK.buf, kdcData.GTK.buf, (sizeof(u_int8_t) * kdcData.GTK.len));
        packet->kdc_data.GTK.len = kdcData.GTK.len;

        packet->kdc_data.nonce = kdcData.nonce;

        packet->kdc_data.CRL.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.CRL.len));
        memcpy(packet->kdc_data.CRL.buf, kdcData.CRL.buf, (sizeof(u_int8_t) * kdcData.CRL.len));
        packet->kdc_data.CRL.len = kdcData.CRL.len;

        packet->kdc_data.cert_kdc.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.cert_kdc.len));
        memcpy(packet->kdc_data.cert_kdc.buf, kdcData.cert_kdc.buf, (sizeof(u_int8_t) * kdcData.cert_kdc.len));
        packet->kdc_data.cert_kdc.len = kdcData.cert_kdc.len;

        packet->kdc_data.sign.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.sign.len));
        memcpy(packet->kdc_data.sign.buf, kdcData.sign.buf, (sizeof(u_int8_t) * kdcData.sign.len));
        packet->kdc_data.sign.len = kdcData.sign.len;

        packet->kdc_data.key_nr = kdcData.key_nr;

        packet->kdc_data.sign_key.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * kdcData.sign_key.len));
        memcpy(packet->kdc_data.sign_key.buf, kdcData.sign_key.buf, (sizeof(u_int8_t) * kdcData.sign_key.len));
        packet->kdc_data.sign_key.len = kdcData.sign_key.len;
    } else {
        packet->kdc_data.GTK.buf = NULL;
        packet->kdc_data.GTK.len = 0;
        packet->kdc_data.nonce = 0;
        packet->kdc_data.CRL.buf = NULL;
        packet->kdc_data.CRL.len = 0;
        packet->kdc_data.cert_kdc.buf = NULL;
        packet->kdc_data.cert_kdc.len = 0;
        packet->kdc_data.sign.buf = NULL;
        packet->kdc_data.sign.len = 0;
        packet->kdc_data.key_nr = 0;
        packet->kdc_data.sign_key.buf = NULL;
        packet->kdc_data.sign_key.len = 0;
    }
    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoDestination.lat = myGeo.lat;
    packet->geoDestination.lon = myGeo.lon;
    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    int next_iv = 0;
    u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
    packet->auth = root->getNextSecret(&next_iv, secret);
    //set new sequence number, because "root->getNextSecret" can increase it
    packet->seq = pGlobal->getSeqNr();
    packet->secret = secret;

    crypto_hash->computeHmacTURREP(packet, pGlobal->getGTK());

    // send packet
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "TU-RREP info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREP.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, forw_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    pGlobal->incSeqNr();
    return packet;
}

PASER_TU_RREP_ACK * PASER_packet_sender::send_tu_rrep_ack(struct in_addr src_addr, struct in_addr dest_addr) {
    PASER_TU_RREP_ACK *packet = new PASER_TU_RREP_ACK(src_addr, dest_addr, pGlobal->getSeqNr());
    packet->keyNr = pGlobal->getKeyNr();
    int next_iv = 0;
    u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
    packet->auth = root->getNextSecret(&next_iv, secret);
    //set new sequence number, because "root->getNextSecret" can increase it
    packet->seq = pGlobal->getSeqNr();
    packet->secret = secret;

    crypto_hash->computeHmacTURREPACK(packet, pGlobal->getGTK());

    // send packet
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(dest_addr);
    if (nEntry == NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't find neighbor.\n");
        delete packet;
        return NULL;
    }
    pGlobal->incSeqNr();
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "TU-RREP-ACK info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREP-ACK.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, dest_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));
    return packet;
}

void PASER_packet_sender::send_rerr(std::list<unreachableBlock> unreachableList) {
    if (unreachableList.size() == 1) {
        struct timeval now;
        pGlobal->getPASERtimeofday(&now);

        if (!pGlobal->getBlacklist()->setRerrTime(unreachableList.front().addr, now)) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "RRER to node %s is already send.\n", inet_ntoa(unreachableList.front().addr));
            return;
        }
    }

    for (u_int32_t i = 0; i < paser_configuration->getNetDeviceNumber(); i++) {
        PASER_TB_RERR *packetToSend = new PASER_TB_RERR(paser_configuration->getNetDevice()[i].ipaddr, pGlobal->getSeqNr());
        packetToSend->keyNr = pGlobal->getKeyNr();

        std::list<unreachableBlock> tempList(unreachableList);
        std::list<unreachableBlock> UnreachableAdressesList;
        for (std::list<unreachableBlock>::iterator it = tempList.begin(); it != tempList.end(); it++) {
            unreachableBlock bLock;
            bLock.addr.s_addr = ((unreachableBlock) *it).addr.s_addr;
            bLock.seq = ((unreachableBlock) *it).seq;
            UnreachableAdressesList.push_back(bLock);
        }
        packetToSend->UnreachableAdressesList.assign(UnreachableAdressesList.begin(), UnreachableAdressesList.end());

        geo_pos myGeo = pGlobal->getGeoPosition();
        packetToSend->geoForwarding.lat = myGeo.lat;
        packetToSend->geoForwarding.lon = myGeo.lon;

        int next_iv = 0;
        u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
        packetToSend->auth = pGlobal->getRoot()->getNextSecret(&next_iv, secret);
        //set new sequence number, because "root->getNextSecret" can increase it
        packetToSend->seq = pGlobal->getSeqNr();
        packetToSend->secret = secret;

        pGlobal->getCrypto_hash()->computeHmacRERR(packetToSend, pGlobal->getGTK());

        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Send RRER. Dest: %s.\n", inet_ntoa(unreachableList.front().addr));
        // send packet
        struct in_addr bcast_addr;
        bcast_addr.s_addr = PASER_BROADCAST;
        pGlobal->incSeqNr();
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "RRER info:\n%s", packetToSend->detailedInfo().c_str());
        //Convert packet object to byte array
        uint8_t *packetBuf;
        int packetLenth = 0;
        packetBuf = packetToSend->getCompleteByteArray(&packetLenth);
        if (!packetBuf) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create RERR.\n");
            delete packetToSend;
            return;
        }
        //send byte array
        pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
                &(paser_configuration->getNetDevice()[i]));

        delete packetToSend;
    }
}

void PASER_packet_sender::send_root() {
    for (u_int32_t i = 0; i < paser_configuration->getNetDeviceNumber(); i++) {
        PASER_B_ROOT *packetToSend = new PASER_B_ROOT(paser_configuration->getNetDevice()[i].ipaddr, pGlobal->getSeqNr());

        struct timeval now;
        pGlobal->getPASERtimeofday(&now);
        packetToSend->timestamp = now.tv_sec;

        geo_pos myGeo = pGlobal->getGeoPosition();
        packetToSend->geoQuerying.lat = myGeo.lat;
        packetToSend->geoQuerying.lon = myGeo.lon;

        lv_block cert;
        if (!crypto_sign->getCert(&cert)) {
            return;
        }
        packetToSend->cert.buf = cert.buf;
        packetToSend->cert.len = cert.len;

        packetToSend->root = root->getRoot();
        packetToSend->initVector = root->getIV();

        crypto_sign->signB_ROOT(packetToSend);

        // send packet
        struct in_addr bcast_addr;
        bcast_addr.s_addr = PASER_BROADCAST;
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "ROOT info:\n%s", packetToSend->detailedInfo().c_str());
        //Convert packet object to byte array
        uint8_t *packetBuf;
        int packetLenth = 0;
        packetBuf = packetToSend->getCompleteByteArray(&packetLenth);
        if (!packetBuf) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create ROOT.\n");
            delete packetToSend;
            return;
        }
        //send byte array
        pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
                &(paser_configuration->getNetDevice()[i]));

        pGlobal->incSeqNr();
        delete packetToSend;
    }
}

void PASER_packet_sender::send_reset() {
    for (u_int32_t i = 0; i < paser_configuration->getNetDeviceNumber(); i++) {
        PASER_RESET *packetToSend = new PASER_RESET(paser_configuration->getNetDevice()[i].ipaddr);

        packetToSend->keyNr = pGlobal->getKeyNr();

        lv_block tempCert;
        pGlobal->getKDCCert(&tempCert);

        packetToSend->cert.len = tempCert.len;
        packetToSend->cert.buf = tempCert.buf;

        lv_block tempSign;

        pGlobal->getRESETSign(&tempSign);
        packetToSend->sign.len = tempSign.len;
        packetToSend->sign.buf = tempSign.buf;

        struct in_addr bcast_addr;
        bcast_addr.s_addr = PASER_BROADCAST;
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "RESET info:\n%s", packetToSend->detailedInfo().c_str());
        uint8_t *packetBuf;
        int packetLenth = 0;
        for (int j = 0; j < 1; j++) {
            // send packet
            //Convert packet object to byte array
            packetBuf = packetToSend->getCompleteByteArray(&packetLenth);
            if (!packetBuf) {
                PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create RESET.\n");
                delete packetToSend;
                return;
            }
            //send byte array
            pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
                    &(paser_configuration->getNetDevice()[i]));
        }
        // send packet
        //Convert packet object to byte array
        packetBuf = packetToSend->getCompleteByteArray(&packetLenth);
        if (!packetBuf) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create RESET.\n");
            delete packetToSend;
            return;
        }
        //send byte array
        pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
                &(paser_configuration->getNetDevice()[i]));

        delete packetToSend;
    }
}

PASER_UB_RREQ * PASER_packet_sender::forward_ub_rreq(PASER_UB_RREQ *oldPacket) {
    //forward UB-REEQ on all interfaces
    PASER_UB_RREQ *packet = NULL;
    for (u_int32_t i = 0; i < paser_configuration->getNetDeviceNumber(); i++) {
        if (i > 0) {
            delete packet;
        }
        packet = new PASER_UB_RREQ(*oldPacket);
        struct timeval now;
        pGlobal->getPASERtimeofday(&now);
        packet->timestamp = now.tv_sec;
        packet->seqForw = pGlobal->getSeqNr();
        packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
        in_addr WlanAddrStruct;
        WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[i].ipaddr.s_addr;
        address_list myAddrList;
        myAddrList.ipaddr = WlanAddrStruct;
        myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
        packet->AddressRangeList.push_back(myAddrList);
        packet->metricBetweenQueryingAndForw = packet->metricBetweenQueryingAndForw + 1;

        lv_block certForw;
        free(packet->certForw.buf);
        if (!crypto_sign->getCert(&certForw)) {
            return NULL;
        }
        packet->certForw.buf = certForw.buf;
        packet->certForw.len = certForw.len;
        free(packet->root);
        packet->root = root->getRoot();
        packet->initVector = root->getIV();

        geo_pos myGeo = pGlobal->getGeoPosition();

        packet->geoForwarding.lat = myGeo.lat;
        packet->geoForwarding.lon = myGeo.lon;

        crypto_sign->signUBRREQ(packet);

        // send Packet
        struct in_addr bcast_addr;
        bcast_addr.s_addr = (in_addr_t) 0xFFFFFFFF;
        //Convert packet object to byte array
        uint8_t *packetBuf;
        int packetLenth = 0;
        packetBuf = packet->getCompleteByteArray(&packetLenth);
        if (!packetBuf) {
            PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREP-ACK.\n");
            delete packet;
            return NULL;
        }
        //send byte array
        pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, bcast_addr, PASER_PORT,
                &(paser_configuration->getNetDevice()[i]));

    }
    if (packet != NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "UB-RREQ info:\n%s", packet->detailedInfo().c_str());
    } else {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "UB-RREQ is NULL pointer\n");
    }
    pGlobal->incSeqNr();
    if (pGlobal->getPaser_configuration()->isResetHelloByBroadcast()) {
        pGlobal->resetHelloTimer();
    }
    return packet;
}

PASER_TU_RREQ * PASER_packet_sender::forward_ub_rreq_to_tu_rreq(PASER_UB_RREQ *oldPacket, struct in_addr nxtHop_addr,
        struct in_addr dest_addr) {
    PASER_TU_RREQ *packet = new PASER_TU_RREQ(oldPacket->srcAddress_var, dest_addr, oldPacket->seq);
    packet->keyNr = pGlobal->getKeyNr();
    packet->seqForw = pGlobal->getSeqNr();
    packet->searchGW = oldPacket->searchGW;
    packet->GFlag = oldPacket->GFlag;
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nxtHop_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenQueryingAndForw = oldPacket->metricBetweenQueryingAndForw + 1;

    if (packet->GFlag) {
        //Falls auf GW sesucht wird, wird nonce und Zertifikat weitergeleitet
        //nonce
        packet->nonce = oldPacket->nonce;
        //cert
        packet->cert.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->cert.len));
        memcpy(packet->cert.buf, oldPacket->cert.buf, (sizeof(u_int8_t) * oldPacket->cert.len));
        packet->cert.len = oldPacket->cert.len;

    }
    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoQuerying.lat = oldPacket->geoQuerying.lat;
    packet->geoQuerying.lon = oldPacket->geoQuerying.lon;
    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
    int next_iv = 0;
    packet->auth = root->getNextSecret(&next_iv, secret);
    //set new sequence number, because "root->getNextSecret" can increase it
    packet->seqForw = pGlobal->getSeqNr();
    packet->secret = secret;
    crypto_hash->computeHmacTURREQ(packet, pGlobal->getGTK());

    // send packet
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "TU-RREQ info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREQ.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, nxtHop_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    pGlobal->incSeqNr();
    return packet;
}

PASER_UU_RREP * PASER_packet_sender::forward_uu_rrep(PASER_UU_RREP *oldPacket, struct in_addr nxtHop_addr) {
    PASER_UU_RREP *packet = new PASER_UU_RREP(*oldPacket);
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    packet->timestamp = now.tv_sec;
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nxtHop_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenDestAndForw = packet->metricBetweenDestAndForw + 1;

    free(packet->root);
    packet->root = root->getRoot();
    packet->initVector = root->getIV();
    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    if (packet->certForw.len > 0) {
        packet->certForw.len = 0;
        free(packet->certForw.buf);
    }
    lv_block certForw;
    if (!crypto_sign->getCert(&certForw)) {
        delete packet;
        return NULL;
    }
    packet->certForw.buf = certForw.buf;
    packet->certForw.len = certForw.len;

    crypto_sign->signUURREP(packet);

    // send packet
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "UU-RREP info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create UU-RREP.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, nxtHop_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    pGlobal->incSeqNr();
    return packet;
}

PASER_TU_RREP * PASER_packet_sender::forward_uu_rrep_to_tu_rrep(PASER_UU_RREP *oldPacket, struct in_addr nxtHop_addr) {
    PASER_TU_RREP *packet = new PASER_TU_RREP(oldPacket->srcAddress_var, oldPacket->destAddress_var, oldPacket->seq);
    packet->keyNr = pGlobal->getKeyNr();
    packet->searchGW = oldPacket->searchGW;
    packet->GFlag = oldPacket->GFlag;
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nxtHop_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenQueryingAndForw = oldPacket->metricBetweenQueryingAndForw;
    packet->metricBetweenDestAndForw = oldPacket->metricBetweenDestAndForw + 1;

    packet->geoDestination.lat = oldPacket->geoDestination.lat;
    packet->geoDestination.lon = oldPacket->geoDestination.lon;
    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    if (oldPacket->GFlag) {
        packet->kdc_data.GTK.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.GTK.len));
        memcpy(packet->kdc_data.GTK.buf, oldPacket->kdc_data.GTK.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.GTK.len));
        packet->kdc_data.GTK.len = oldPacket->kdc_data.GTK.len;

        packet->kdc_data.nonce = oldPacket->kdc_data.nonce;

        packet->kdc_data.CRL.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.CRL.len));
        memcpy(packet->kdc_data.CRL.buf, oldPacket->kdc_data.CRL.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.CRL.len));
        packet->kdc_data.CRL.len = oldPacket->kdc_data.CRL.len;

        packet->kdc_data.cert_kdc.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.cert_kdc.len));
        memcpy(packet->kdc_data.cert_kdc.buf, oldPacket->kdc_data.cert_kdc.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.cert_kdc.len));
        packet->kdc_data.cert_kdc.len = oldPacket->kdc_data.cert_kdc.len;

        packet->kdc_data.sign.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.sign.len));
        memcpy(packet->kdc_data.sign.buf, oldPacket->kdc_data.sign.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.sign.len));
        packet->kdc_data.sign.len = oldPacket->kdc_data.sign.len;

        packet->kdc_data.key_nr = oldPacket->kdc_data.key_nr;

        packet->kdc_data.sign_key.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.sign_key.len));
        memcpy(packet->kdc_data.sign_key.buf, oldPacket->kdc_data.sign_key.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.sign_key.len));
        packet->kdc_data.sign_key.len = oldPacket->kdc_data.sign_key.len;
    } else {
        packet->kdc_data.GTK.buf = NULL;
        packet->kdc_data.GTK.len = 0;
        packet->kdc_data.nonce = 0;
        packet->kdc_data.CRL.buf = NULL;
        packet->kdc_data.CRL.len = 0;
        packet->kdc_data.cert_kdc.buf = NULL;
        packet->kdc_data.cert_kdc.len = 0;
        packet->kdc_data.sign.buf = NULL;
        packet->kdc_data.sign.len = 0;
        packet->kdc_data.key_nr = 0;
        packet->kdc_data.sign_key.buf = NULL;
        packet->kdc_data.sign_key.len = 0;
    }

    u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
    int next_iv = 0;
    packet->auth = root->getNextSecret(&next_iv, secret);
    //set new sequence number, because "root->getNextSecret" can increase it
    packet->seq = pGlobal->getSeqNr();
    packet->secret = secret;
    crypto_hash->computeHmacTURREP(packet, pGlobal->getGTK());

    // send packet
    pGlobal->incSeqNr();
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "TU-RREP info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREP.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, nxtHop_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    return packet;
}

PASER_TU_RREQ * PASER_packet_sender::forward_tu_rreq(PASER_TU_RREQ *oldPacket, struct in_addr nxtHop_addr) {
    PASER_TU_RREQ *packet = new PASER_TU_RREQ(*oldPacket);
    packet->seqForw = pGlobal->getSeqNr();
    in_addr WlanAddrStruct;
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nxtHop_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenQueryingAndForw = packet->metricBetweenQueryingAndForw + 1;

    if (packet->GFlag) {
        free(packet->cert.buf);
        packet->cert.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->cert.len));
        memcpy(packet->cert.buf, oldPacket->cert.buf, (sizeof(u_int8_t) * oldPacket->cert.len));
        packet->cert.len = oldPacket->cert.len;
    }
    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoQuerying.lat = oldPacket->geoQuerying.lat;
    packet->geoQuerying.lon = oldPacket->geoQuerying.lon;
    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    free(packet->secret);
    for (std::list<u_int8_t *>::iterator it = packet->auth.begin(); it != packet->auth.end(); it++) {
        u_int8_t *data = (u_int8_t *) *it;
        free(data);
    }
    packet->auth.clear();
    free(packet->hash);

    u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
    int next_iv = 0;
    packet->auth = root->getNextSecret(&next_iv, secret);
    //set new sequence number, because "root->getNextSecret" can increase it
    packet->seqForw = pGlobal->getSeqNr();
    packet->secret = secret;
    crypto_hash->computeHmacTURREQ(packet, pGlobal->getGTK());

    // send packet
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "TU-RREQ info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREQ.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, nxtHop_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    pGlobal->incSeqNr();
    return packet;
}

PASER_UU_RREP * PASER_packet_sender::forward_tu_rrep_to_uu_rrep(PASER_TU_RREP *oldPacket, struct in_addr nxtHop_addr) {

    PASER_UU_RREP *packet = new PASER_UU_RREP(oldPacket->srcAddress_var, oldPacket->destAddress_var, oldPacket->seq);
    packet->keyNr = pGlobal->getKeyNr();
    struct timeval now;
    pGlobal->getPASERtimeofday(&now);
    packet->timestamp = now.tv_sec;
    packet->searchGW = oldPacket->searchGW;
    packet->GFlag = oldPacket->GFlag;
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nxtHop_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenQueryingAndForw = oldPacket->metricBetweenQueryingAndForw;
    packet->metricBetweenDestAndForw = oldPacket->metricBetweenDestAndForw + 1;

    lv_block certForw;
    if (!crypto_sign->getCert(&certForw)) {
        return NULL;
    }
    packet->certForw.buf = certForw.buf;
    packet->certForw.len = certForw.len;
    packet->root = root->getRoot();
    packet->initVector = root->getIV();

    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoDestination.lat = oldPacket->geoDestination.lat;
    packet->geoDestination.lon = oldPacket->geoDestination.lon;
    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    if (oldPacket->GFlag) {
        packet->kdc_data.GTK.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.GTK.len));
        memcpy(packet->kdc_data.GTK.buf, oldPacket->kdc_data.GTK.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.GTK.len));
        packet->kdc_data.GTK.len = oldPacket->kdc_data.GTK.len;

        packet->kdc_data.nonce = oldPacket->kdc_data.nonce;

        packet->kdc_data.CRL.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.CRL.len));
        memcpy(packet->kdc_data.CRL.buf, oldPacket->kdc_data.CRL.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.CRL.len));
        packet->kdc_data.CRL.len = oldPacket->kdc_data.CRL.len;

        packet->kdc_data.cert_kdc.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.cert_kdc.len));
        memcpy(packet->kdc_data.cert_kdc.buf, oldPacket->kdc_data.cert_kdc.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.cert_kdc.len));
        packet->kdc_data.cert_kdc.len = oldPacket->kdc_data.cert_kdc.len;

        packet->kdc_data.sign.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.sign.len));
        memcpy(packet->kdc_data.sign.buf, oldPacket->kdc_data.sign.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.sign.len));
        packet->kdc_data.sign.len = oldPacket->kdc_data.sign.len;

        packet->kdc_data.key_nr = oldPacket->kdc_data.key_nr;

        packet->kdc_data.sign_key.buf = (u_int8_t *) malloc((sizeof(u_int8_t) * oldPacket->kdc_data.sign_key.len));
        memcpy(packet->kdc_data.sign_key.buf, oldPacket->kdc_data.sign_key.buf, (sizeof(u_int8_t) * oldPacket->kdc_data.sign_key.len));
        packet->kdc_data.sign_key.len = oldPacket->kdc_data.sign_key.len;
    } else {
        packet->kdc_data.GTK.buf = NULL;
        packet->kdc_data.GTK.len = 0;
        packet->kdc_data.nonce = 0;
        packet->kdc_data.CRL.buf = NULL;
        packet->kdc_data.CRL.len = 0;
        packet->kdc_data.cert_kdc.buf = NULL;
        packet->kdc_data.cert_kdc.len = 0;
        packet->kdc_data.sign.buf = NULL;
        packet->kdc_data.sign.len = 0;
        packet->kdc_data.key_nr = 0;
        packet->kdc_data.sign_key.buf = NULL;
        packet->kdc_data.sign_key.len = 0;
    }

    crypto_sign->signUURREP(packet);

    // send packet
    pGlobal->incSeqNr();
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "UU-RREP info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create UU-RREP.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, nxtHop_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    return packet;
}

PASER_TU_RREP * PASER_packet_sender::forward_tu_rrep(PASER_TU_RREP *oldPacket, struct in_addr nxtHop_addr) {
    PASER_TU_RREP *packet = new PASER_TU_RREP(*oldPacket);
    packet->AddressRangeList.assign(oldPacket->AddressRangeList.begin(), oldPacket->AddressRangeList.end());
    in_addr WlanAddrStruct;
    PASER_neighbor_entry *nEntry = neighbor_table->findNeigh(nxtHop_addr);
    int ifId = paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex);
    WlanAddrStruct.s_addr = paser_configuration->getNetDevice()[ifId].ipaddr.s_addr;
    address_list myAddrList;
    myAddrList.ipaddr = WlanAddrStruct;
    myAddrList.range = pGlobal->getPaser_configuration()->getAddL();
    packet->AddressRangeList.push_back(myAddrList);
    packet->metricBetweenDestAndForw = packet->metricBetweenDestAndForw + 1;

    geo_pos myGeo = pGlobal->getGeoPosition();

    packet->geoForwarding.lat = myGeo.lat;
    packet->geoForwarding.lon = myGeo.lon;

    for (std::list<u_int8_t *>::iterator it = packet->auth.begin(); it != packet->auth.end(); it++) {
        u_int8_t *temp = (u_int8_t *) *it;
        free(temp);
    }
    free(packet->secret);
    packet->auth.clear();
    free(packet->hash);

    u_int8_t *secret = (u_int8_t *) malloc((sizeof(u_int8_t) * PASER_SECRET_LEN));
    int next_iv = 0;
    packet->auth = root->getNextSecret(&next_iv, secret);
    //set new sequence number, because "root->getNextSecret" can increase it
    packet->seq = pGlobal->getSeqNr();
    packet->secret = secret;
    crypto_hash->computeHmacTURREP(packet, pGlobal->getGTK());

    // send packet
    pGlobal->incSeqNr();
    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "TU-RREP info:\n%s", packet->detailedInfo().c_str());
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create TU-RREP.\n");
        delete packet;
        return NULL;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverNetwork(packetBuf, packetLenth, nxtHop_addr, PASER_PORT,
            &(paser_configuration->getNetDevice()[paser_configuration->getIfIdFromIfIndex(nEntry->ifIndex)]));

    return packet;
}

void PASER_packet_sender::sendKDCRequest(struct in_addr nodeAddr, struct in_addr nextHop, lv_block cert, int nonce) {
    if (paser_configuration->getNetEthDeviceNumber() < 1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "Cann't find Ethernet adapter\n");
        return;
    }

    PASER_GTKREQ *packet = new PASER_GTKREQ();
    packet->srcAddress_var.s_addr = nodeAddr.s_addr;
    packet->gwAddr.s_addr = paser_configuration->getNetDevice()[0].ipaddr.s_addr;
    packet->nextHopAddr.s_addr = nextHop.s_addr;
    packet->cert.len = cert.len;
    packet->cert.buf = (uint8_t *) malloc(cert.len);
    memcpy(packet->cert.buf, cert.buf, cert.len);
    packet->nonce = nonce;

    // send Packet
    //Convert packet object to byte array
    uint8_t *packetBuf;
    int packetLenth = 0;
    packetBuf = packet->getCompleteByteArray(&packetLenth);
    if (!packetBuf) {
        PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_PROCESSING, "Cann't create GTK Request.\n");
        delete packet;
        return;
    }
    //send byte array
    pGlobal->getPASER_socket()->sendUDPToIPOverSSL(packetBuf, packetLenth, pGlobal->getPaser_configuration()->getAddressOfKDC(),
            PASER_PORT_KDC, &(paser_configuration->getNetEthDevice()[0]));

    PASER_LOG_WRITE_LOG(PASER_LOG_PACKET_INFO, "PASER_GTKREQ info:\n%s", packet->detailedInfo().c_str());
    delete packet;
}
