/**
 *\class  		PASER_packet_sender
 *@brief       	Class provides functions for working with all PASER messages (sender)
 *@ingroup		PP
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

class PASER_packet_sender;

#ifndef PASER_PACKET_SENDER_H_
#define PASER_PACKET_SENDER_H_

#include "../config/PASER_defs.h"
#include "../config/PASER_global.h"
#include "../packet_structure/PASER_GTKREQ.h"
#include "../packet_structure/PASER_GTKRESET.h"
#include "../packet_structure/PASER_GTKREP.h"
#include "../packet_structure/PASER_B_ROOT.h"
#include "../packet_structure/PASER_TB_HELLO.h"
#include "../packet_structure/PASER_MSG.h"
#include "../packet_structure/PASER_TB_RERR.h"
#include "../packet_structure/PASER_RESET.h"
#include "../packet_structure/PASER_TU_RREP.h"
#include "../packet_structure/PASER_TU_RREP_ACK.h"
#include "../packet_structure/PASER_TU_RREQ.h"
#include "../packet_structure/PASER_UB_RREQ.h"
#include "../packet_structure/PASER_UU_RREP.h"

#include "../crypto/PASER_root.h"
#include "../crypto/PASER_crypto_hash.h"
#include "../crypto/PASER_crypto_sign.h"
#include "../tables/PASER_routing_table.h"
#include "../tables/PASER_neighbor_table.h"

class PASER_packet_sender {
private:
    PASER_global *pGlobal;
    PASER_config *paser_configuration;

    PASER_root *root;
    PASER_crypto_sign *crypto_sign;
    PASER_crypto_hash *crypto_hash;
    PASER_routing_table *routing_table;
    PASER_neighbor_table *neighbor_table;
public:
    PASER_packet_sender(PASER_global* paser_global);
    virtual ~PASER_packet_sender();

    void init();

    /**
     * Functions to create, secure and send a PASER packets.
     *
     *@return pointer to created packet
     */
    PASER_UB_RREQ * send_ub_rreq(struct in_addr src_addr, struct in_addr dest_addr, int isDestGW);
    PASER_UU_RREP * send_uu_rrep(struct in_addr src_addr, struct in_addr forw_addr, struct in_addr dest_addr, int isDestGW, X509 *cert,
            kdc_block kdcData);
    PASER_TU_RREP * send_tu_rrep(struct in_addr src_addr, struct in_addr forw_addr, struct in_addr dest_addr, int isDestGW, X509 *cert,
            kdc_block kdcData);
    PASER_TU_RREP_ACK * send_tu_rrep_ack(struct in_addr src_addr, struct in_addr dest_addr);
    void send_rerr(std::list<unreachableBlock> unreachableList);
    void send_root();
    void send_reset();
    /*--------------------------------------------------------*/

    /**
     * Send KDC registration request. The request will be sent over Ethernet.
     * The function can be called only by a gateway.
     *
     *@param nodeAddr IP address of the registered node
     *@param nextHop IP address of the next hop node to the registered node
     *@param cert certificate of the registered node
     *@param nonce nonce of the registered node
     */
    void sendKDCRequest(struct in_addr nodeAddr, struct in_addr nextHop, lv_block cert, int nonce);

    /**
     * Functions to forward a PASER packets.
     */
    PASER_UB_RREQ * forward_ub_rreq(PASER_UB_RREQ *oldPacket);
    PASER_TU_RREQ * forward_ub_rreq_to_tu_rreq(PASER_UB_RREQ *oldPacket, struct in_addr nxtHop_addr, struct in_addr dest_addr);
    PASER_UU_RREP * forward_uu_rrep(PASER_UU_RREP *oldPacket, struct in_addr nxtHop_addr);
    PASER_TU_RREP * forward_uu_rrep_to_tu_rrep(PASER_UU_RREP *oldPacket, struct in_addr nxtHop_addr);
    PASER_TU_RREQ * forward_tu_rreq(PASER_TU_RREQ *oldPacket, struct in_addr nxtHop_addr);
    PASER_UU_RREP * forward_tu_rrep_to_uu_rrep(PASER_TU_RREP *oldPacket, struct in_addr nxtHop_addr);
    PASER_TU_RREP * forward_tu_rrep(PASER_TU_RREP *oldPacket, struct in_addr nxtHop_addr);
    /*--------------------------------------------------------*/
};

#endif /* PASER_PACKET_SENDER_H_ */
