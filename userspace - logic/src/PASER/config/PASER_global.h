/**
 *\class  		PASER_global
 *@brief       	Class implements the main functions of PASER.
 *@ingroup		Configuration
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

class PASER_global;

#ifndef PASER_GLOBAL_H_
#define PASER_GLOBAL_H_

#include "PASER_defs.h"
#include "PASER_config.h"
#include "../route_discovery/PASER_route_discovery.h"
#include "../route_maintenance/PASER_route_maintenance.h"
#include "../packet_processing/PASER_packet_processing.h"
#include "../packet_processing/PASER_blacklist.h"
#include "../packet_processing/PASER_packet_sender.h"
#include "../crypto/PASER_crypto_hash.h"
#include "../crypto/PASER_root.h"
#include "../crypto/PASER_crypto_sign.h"
#include "../timer_management/PASER_timer_queue.h"
#include "../syslog/PASER_syslog.h"
#include "../tables/PASER_neighbor_table.h"
#include "../tables/PASER_routing_table.h"
#include "../tables/PASER_rreq_list.h"
#include "../paser_socket/PASER_socket.h"
#include "../scheduler/PASER_scheduler.h"
#include "../statistics/PASER_statistics.h"
#include "../gps/PASER_gpsReader.h"

/**
 * This class provides pointer to all PASER Modules.
 */
class PASER_global {
public:
    /**
     * Constructor which should initialize all other modules
     */
    PASER_global(PASER_config *pConfig, PASER_syslog * tmplog);
    ~PASER_global();

    PASER_socket *getPASER_socket();
    PASER_scheduler *getScheduler();
    PASER_crypto_hash *getCrypto_hash();
    PASER_crypto_sign *getCrypto_sign();
    PASER_neighbor_table *getNeighbor_table();
    PASER_routing_table *getRouting_table();
//    PASER_packet_queue *getPacket_queue();
    PASER_root *getRoot();
    PASER_rreq_list *getRrep_list();
    PASER_rreq_list *getRreq_list();
    PASER_timer_queue *getTimer_queue();
    PASER_config *getPaser_configuration();
    PASER_blacklist *getBlacklist();
    PASER_packet_sender *getPacketSender();
    PASER_packet_processing *getPacket_processing();
    PASER_route_discovery *getRoute_findung();
    PASER_route_maintenance *getRoute_maintenance();
    PASER_syslog * getSyslog();
    PASER_statistics * getPaserStatistic();

    void resetHelloTimer();
    void activateHelloPacketTimer();

    bool getIsRegistered();
    void setIsRegistered(bool i);
    bool getWasRegistered();
    void setWasRegistered(bool i);
    u_int32_t getSeqNr();
    void incSeqNr();
    u_int32_t getLastGwSearchNonce();
    void generateGwSearchNonce();
    void setLastGwSearchNonce(u_int32_t s);

    void setGTK(lv_block _GTK);
    lv_block getGTK();

    void setKDC_cert(lv_block _KDC_cert);
    void getKDCCert(lv_block *t);
    lv_block getKDC_cert();

    void setRESET_sign(lv_block _RESET_sign);
    void getRESETSign(lv_block *s);
    lv_block getRESET_sign();

    void setKeyNr(u_int32_t k);
    u_int32_t getKeyNr();

    geo_pos getGeoPosition();

    /**
     * RESET all PASER Configuration and delete all PASER Tables
     */
    void resetPASER();

    bool isSeqNew(u_int32_t oldSeq, u_int32_t newSeq);

    /**
     * get geo position
     */
    double getLatPos();
    double getLonPos();

    /**
     * Get Time when an event has occurred
     */
    int getPASERtimeofday(struct timeval *val);

    /**
     * Update Time. Should be called one time per event.
     */
    void UpdateTime();

private:
    PASER_socket *socket;
    PASER_scheduler *scheduler;
    PASER_timer_queue *timer_queue;
    PASER_routing_table *routing_table;
    PASER_neighbor_table *neighbor_table;
//    PASER_packet_queue *packet_queue;
    PASER_config *paser_configuration;
    PASER_packet_processing *packet_processing;
    PASER_route_discovery *route_findung;
    PASER_route_maintenance *route_maintenance;
    PASER_syslog *Syslog;

    PASER_rreq_list *rreq_list;
    PASER_rreq_list *rrep_list;

    PASER_root *root;
    PASER_crypto_sign *crypto_sign;
    PASER_crypto_hash *crypto_hash;

    PASER_blacklist *blackList;
    PASER_packet_sender *packetSender;

    PASER_statistics *paserStats;
    GPSDATA::PASER_GPS* gpsReader;

    u_int32_t seqNr;

    lv_block GTK;                           ///< Current GTK
    u_int32_t key_nr;                       ///< Current number of GTK
    lv_block KDC_cert;                      ///< Certificate of KDC
    lv_block RESET_sign;                    ///< Signature of RESET message

    u_int32_t lastGwSearchNonce;

    bool isRegistered;
    bool wasRegistered;

    timeval PASER_time;
    int PASER_time_status;

//    timeval HELLO_time;
    PASER_timer_packet *hello_packet_interval;
};

#endif /* PASER_GLOBAL_H_ */
