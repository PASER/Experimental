/**
 *\class  		PASER_packet_processing
 *@brief       	Class provides functions for working with all PASER messages (processing)
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

class PASER_packet_processing;

#ifndef PASER_PACKET_PROCESSING_H_
#define PASER_PACKET_PROCESSING_H_

#include "PASER_packet_sender.h"

#include "../config/PASER_config.h"
#include "../config/PASER_global.h"
#include "../route_discovery/PASER_route_discovery.h"
#include "../tables/PASER_rreq_list.h"
#include "../crypto/PASER_root.h"
#include "../crypto/PASER_crypto_hash.h"
#include "../crypto/PASER_crypto_sign.h"
#include "../route_maintenance/PASER_route_maintenance.h"
#include "../timer_management/PASER_timer_queue.h"
#include "../tables/PASER_neighbor_table.h"
#include "../tables/PASER_routing_table.h"


/**
 * The class provides functions for working with all PASER messages.
 */
class PASER_packet_processing {
private:
    network_device *netDevice; ///< pointer to an Array of wireless cards on which PASER is running

    /**
     * Pointers to other modules. The modules are defined
     * in PASER_global.
     */
    PASER_global *pGlobal;
    PASER_config *paser_configuration;

    PASER_packet_sender *packet_sender;

    PASER_timer_queue *timer_queue;
    PASER_routing_table *routing_table;
    PASER_neighbor_table *neighbor_table;
//    PASER_packet_queue *packet_queue;
    PASER_root *root;
    PASER_crypto_sign *crypto_sign;
    PASER_crypto_hash *crypto_hash;
    PASER_route_discovery *route_findung;

    PASER_rreq_list *rreq_list; ///< List of IP addresses to which a route discovery is started.
    PASER_rreq_list *rrep_list; ///< List of IP addresses from which a TU-RREP-ACK is expected.

public:
    PASER_packet_processing(PASER_global *pGlobal, PASER_config *pConfig);
    ~PASER_packet_processing();
    /**
     * Initialize parameters
     */
    void init();

    /**
     * Process a newly received PASER packet. Checks the type
     * to the necessary conversions and call the
     * corresponding functions to handle the information.
     */
    void handleLowerMsg(uint8_t *s, int length, u_int32_t ifIndex);

private:
    /**
     * Cast incoming char array to PASER packet.
     *
     *@return PASER packet on success or NULL on error
     */
    PASER_MSG *castToPaserPacket(uint8_t *s, int length);

    /**
     * Checks the sequence number of the PASER message
     *
     * @param paser_msg pointer to the message
     * @param forwarding IP address of the node which forwarded the message
     * @return 1 if the message is new
     *        else 0
     */
    int check_seq_nr(PASER_MSG *paser_msg, struct in_addr forwarding);

    /**
     * Check if the specified position is in the range of own wireless card.
     *
     *@param position Geo Position
     *
     *@return 1 if the <b>position</b> is in the range of own wireless card
     *        else 0.
     */
    int check_geo(geo_pos position);

    /**
     * Check if IP address of own wireless card is in the list.
     *
     *@param rList List of IP addresses
     *
     *@return 1 IP address of own wireless card is in the list
     *        else 0.
     */
    int checkRouteList(std::list<address_list> rList);

    /**
     * Functions to process a newly received PASER packets. Check the packets,
     * edit routing and neighbor tables, set timer and send a reply or forward
     * the packets if necessary.
     */
    void handleUBRREQ(PASER_MSG * msg, u_int32_t ifIndex);
    void handleUURREP(PASER_MSG * msg, u_int32_t ifIndex);
    void handleTURREQ(PASER_MSG * msg, u_int32_t ifIndex);
    void handleTURREP(PASER_MSG * msg, u_int32_t ifIndex);
    void handleTURREPACK(PASER_MSG * msg, u_int32_t ifIndex);
    void handleRERR(PASER_MSG * msg, u_int32_t ifIndex);
    void handleHELLO(PASER_MSG * msg, u_int32_t ifIndex);
    void handleB_ROOT(PASER_MSG * msg, u_int32_t ifIndex);
    void handleB_RESET(PASER_MSG * msg, u_int32_t ifIndex);
    /*--------------------------------------------------------*/

    /**
     * Check the KDC registration Reply. Send a Reply to the registered node if necessary.
     */
    void handleKDCReply(PASER_MSG *kdc_resp);

    /**
     *  Delete an IP address from <b>rreq_list</b> and the responsible timer from timer management.
     *
     * @param dest_addr IP address to delete
     */
    void deleteRouteRequestTimeout(struct in_addr dest_addr);

    /**
     *  Delete a List of IP addresses from <b>rreq_list</b> and the responsible timer from timer management.
     *
     * @param AddList List of IP addresses to delete
     */
    void deleteRouteRequestTimeoutForAddList(std::list<address_list> AddList);

};

#endif /* PASER_PACKET_PROCESSING_H_ */
