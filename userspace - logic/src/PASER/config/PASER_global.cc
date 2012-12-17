/**
 *\class  		PASER_global
 *@brief       	Class implements the main functions of PASER.
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

#include "PASER_global.h"

PASER_global::PASER_global(PASER_config *pConfig, PASER_syslog* tmplog) {

    paser_configuration = pConfig;
//    Syslog = new PASER_syslog(paser_configuration->getLog());
    Syslog = tmplog;

    timer_queue = new PASER_timer_queue();
    neighbor_table = new PASER_neighbor_table(this);
    routing_table = new PASER_routing_table(this);
//    packet_queue = new PASER_packet_queue(pModul);
    rreq_list = new PASER_rreq_list();
    rrep_list = new PASER_rreq_list();

    blackList = new PASER_blacklist();
    packetSender = new PASER_packet_sender(this);
    route_findung = new PASER_route_discovery(this);
    route_maintenance = new PASER_route_maintenance(this);

    root = new PASER_root(this);

    paserStats = new PASER_statistics(this);

    packet_processing = new PASER_packet_processing(this, paser_configuration);

    crypto_sign = new PASER_crypto_sign(paser_configuration->getCertfile(), paser_configuration->getKeyfile(),
            paser_configuration->getCAfile(), this);

    crypto_hash = new PASER_crypto_hash(this);

    socket = new PASER_socket(this);
    scheduler = new PASER_scheduler(this);

    gpsReader = new GPSDATA::PASER_GPS(this);
    gpsReader->startGPS();

    root->init(PASER_root_param);
    packetSender->init();
    packet_processing->init();

    isRegistered = false;
    wasRegistered = false;

    GTK.buf = NULL;
    GTK.len = 0;
    KDC_cert.buf = NULL;
    KDC_cert.len = 0;
    RESET_sign.buf = NULL;
    RESET_sign.len = 0;

    seqNr = 1;

    lastGwSearchNonce = 0;

    PASER_time_status = -1;
    PASER_time.tv_sec = 0;
    PASER_time.tv_usec = 0;

    hello_packet_interval = NULL;
    activateHelloPacketTimer();

    key_nr = 0;

    UpdateTime();
}

PASER_global::~PASER_global() {
    delete crypto_sign;
    delete crypto_hash;
    delete root;
    delete timer_queue;
    delete neighbor_table;
    delete routing_table;
//    delete packet_queue;
    delete rreq_list;
    delete rrep_list;
    delete blackList;
    delete packetSender;
    delete route_findung;
    delete route_maintenance;
    delete Syslog;
    delete packet_processing;
    delete paserStats;
    delete scheduler;
    delete socket;

    if (GTK.len != 0) {
        free(GTK.buf);
        GTK.len = 0;
    }

    if (KDC_cert.len != 0) {
        free(KDC_cert.buf);
        KDC_cert.len = 0;
    }

    if (RESET_sign.len != 0) {
        free(RESET_sign.buf);
        RESET_sign.len = 0;
    }
}

PASER_scheduler *PASER_global::getScheduler() {
    return scheduler;
}

PASER_crypto_hash *PASER_global::getCrypto_hash() {
    return crypto_hash;
}

PASER_crypto_sign *PASER_global::getCrypto_sign() {
    return crypto_sign;
}

lv_block PASER_global::getGTK() {
    return GTK;
}

bool PASER_global::getIsRegistered() {
    return isRegistered;
}

bool PASER_global::getWasRegistered() {
    return wasRegistered;
}

PASER_neighbor_table *PASER_global::getNeighbor_table() {
    return neighbor_table;
}

PASER_routing_table *PASER_global::getRouting_table() {
    return routing_table;
}

//PASER_packet_queue *PASER_global::getPacket_queue()
//{
//    return packet_queue;
//}

PASER_root *PASER_global::getRoot() {
    return root;
}

PASER_rreq_list *PASER_global::getRrep_list() {
    return rrep_list;
}

PASER_rreq_list *PASER_global::getRreq_list() {
    return rreq_list;
}

u_int32_t PASER_global::getSeqNr() {
    return seqNr;
}

u_int32_t PASER_global::getKeyNr() {
    return key_nr;
}

u_int32_t PASER_global::getLastGwSearchNonce() {
    return lastGwSearchNonce;
}

PASER_timer_queue *PASER_global::getTimer_queue() {
    return timer_queue;
}

PASER_config *PASER_global::getPaser_configuration() {
    return paser_configuration;
}

PASER_syslog *PASER_global::getSyslog() {
    return Syslog;
}

PASER_socket *PASER_global::getPASER_socket() {
    return socket;
}

PASER_blacklist *PASER_global::getBlacklist() {
    return blackList;
}

PASER_packet_sender *PASER_global::getPacketSender() {
    return packetSender;
}

PASER_packet_processing *PASER_global::getPacket_processing() {
    return packet_processing;
}

PASER_route_discovery *PASER_global::getRoute_findung() {
    return route_findung;
}

PASER_route_maintenance *PASER_global::getRoute_maintenance() {
    return route_maintenance;
}

PASER_statistics * PASER_global::getPaserStatistic() {
    return paserStats;
}

void PASER_global::setKeyNr(u_int32_t k) {
    key_nr = k;
}

void PASER_global::incSeqNr() {
    seqNr++;
    if (seqNr > PASER_MAXSEQ - 2) {
        seqNr = 1;
    }
}

void PASER_global::setLastGwSearchNonce(u_int32_t s) {
    lastGwSearchNonce = s;
}

void PASER_global::generateGwSearchNonce() {
    lastGwSearchNonce = 0;
    while (!RAND_bytes((uint8_t*) &lastGwSearchNonce, sizeof(lastGwSearchNonce))) {
    };
}

void PASER_global::setWasRegistered(bool i) {
    wasRegistered = i;
}

void PASER_global::setIsRegistered(bool i) {
    isRegistered = i;
}

geo_pos PASER_global::getGeoPosition() {
    geo_pos myGeo;
    myGeo.lat = getLatPos();
    myGeo.lon = getLonPos();
    return myGeo;
}

double PASER_global::getLatPos() {
    return gpsReader->getLatitude();
}

double PASER_global::getLonPos() {
    return gpsReader->getLongitude();
}

void PASER_global::activateHelloPacketTimer() {
    if (hello_packet_interval == NULL) {
        hello_packet_interval = new PASER_timer_packet();
        hello_packet_interval->data = NULL;
        hello_packet_interval->destAddr.s_addr = PASER_BROADCAST;
        hello_packet_interval->handler = HELLO_SEND_TIMEOUT;
        getPASERtimeofday(&(hello_packet_interval->timeout));
        hello_packet_interval->timeout = timeval_add(hello_packet_interval->timeout, PASER_TB_HELLO_Interval);
        timer_queue->timer_add(hello_packet_interval);
        timer_queue->timer_sort();
    }
}

void PASER_global::resetHelloTimer() {
    if (hello_packet_interval == NULL) {
        activateHelloPacketTimer();
        return;
    }
    getPASERtimeofday(&(hello_packet_interval->timeout));
    hello_packet_interval->timeout = timeval_add(hello_packet_interval->timeout, PASER_TB_HELLO_Interval);
    timer_queue->timer_sort();
}

void PASER_global::resetPASER() {
    //reset rreq_list/rrep_list
    rreq_list->clearTable();
    rrep_list->clearTable();

    //reset RoutinigTable
    routing_table->clearTable();

    //reset NeighborTable
    neighbor_table->clearTable();

    //reset TimerQueue
    for (std::list<PASER_timer_packet *>::iterator it = timer_queue->timer_queue.begin(); it != timer_queue->timer_queue.end(); it++) {
        PASER_timer_packet *temp = (PASER_timer_packet*) *it;
        delete temp;
    }
    timer_queue->timer_queue.clear();

    hello_packet_interval = NULL;

    resetHelloTimer();

//    //reset PacketQueue
//    for(std::list<packet_queue_entry>::iterator it = packet_queue->packet_queue_list.begin(); it != packet_queue->packet_queue_list.end(); it++){
//        struct packet_queue_entry temp = (packet_queue_entry)*it;
//        delete temp.p;
//    }
//    packet_queue->packet_queue_list.clear();

//clear Blacklists
    blackList->clearRerrList();

    //delete GTK
    if (GTK.len > 0) {
        free(GTK.buf);
    }
    GTK.len = 0;
    GTK.buf = NULL;

    isRegistered = false;
    wasRegistered = false;
}

bool PASER_global::isSeqNew(u_int32_t oldSeq, u_int32_t newSeq) {
    if (oldSeq == 0) {
        return true;
    }
    if (newSeq == 0) {
        return false;
    }
    if (newSeq > oldSeq && newSeq - oldSeq < (PASER_MAXSEQ / 2)) {
        return true;
    }
    if (newSeq < oldSeq && oldSeq - newSeq > (PASER_MAXSEQ / 2)) {
        return true;
    }
    return false;
}

int PASER_global::getPASERtimeofday(struct timeval *val) {
    if (PASER_time_status == -1) {
        return -1;
    }
    val->tv_sec = PASER_time.tv_sec;
    val->tv_usec = PASER_time.tv_usec;
    return 0;
}

void PASER_global::UpdateTime() {
    PASER_time_status = gettimeofday(&PASER_time, 0);
}

void PASER_global::setGTK(lv_block _GTK) {
    if (GTK.len > 0) {
        free(GTK.buf);
    }
    if (_GTK.len == 0) {
        GTK.len = 0;
        GTK.buf = NULL;
        return;
    }
    GTK.buf = (u_int8_t *) malloc(_GTK.len);
    memcpy(GTK.buf, _GTK.buf, _GTK.len);
    GTK.len = _GTK.len;
}

lv_block PASER_global::getKDC_cert() {
    return KDC_cert;
}

void PASER_global::getKDCCert(lv_block *t) {
    t->len = KDC_cert.len;
    t->buf = (u_int8_t *) malloc((sizeof(u_int8_t) * KDC_cert.len));
    memcpy(t->buf, KDC_cert.buf, (sizeof(u_int8_t) * KDC_cert.len));
}

void PASER_global::setKDC_cert(lv_block _KDC_cert) {
    if (KDC_cert.len > 0) {
        free(KDC_cert.buf);
    }
    if (_KDC_cert.len == 0) {
        KDC_cert.len = 0;
        KDC_cert.buf = NULL;
        return;
    }
    KDC_cert.buf = (u_int8_t *) malloc(_KDC_cert.len);
    memcpy(KDC_cert.buf, _KDC_cert.buf, _KDC_cert.len);
    KDC_cert.len = _KDC_cert.len;
}

lv_block PASER_global::getRESET_sign() {
    return RESET_sign;
}

void PASER_global::getRESETSign(lv_block *s) {
    s->len = RESET_sign.len;
    s->buf = (u_int8_t *) malloc((sizeof(u_int8_t) * RESET_sign.len));
    memcpy(s->buf, RESET_sign.buf, (sizeof(u_int8_t) * RESET_sign.len));
}

void PASER_global::setRESET_sign(lv_block _RESET_sign) {
    if (RESET_sign.len > 0) {
        free(RESET_sign.buf);
    }
    if (_RESET_sign.len == 0) {
        RESET_sign.len = 0;
        RESET_sign.buf = NULL;
        return;
    }
    RESET_sign.buf = (u_int8_t *) malloc(_RESET_sign.len);
    memcpy(RESET_sign.buf, _RESET_sign.buf, _RESET_sign.len);
    RESET_sign.len = _RESET_sign.len;
}
