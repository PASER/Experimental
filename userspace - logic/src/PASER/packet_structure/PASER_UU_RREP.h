/**
 *\class  		PASER_UU_RREP
 *@brief       	Class implements PASER_UU_RREP messages
 *@ingroup		PS
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

#ifndef PASER_UU_RREP_H_
#define PASER_UU_RREP_H_

#include "../config/PASER_defs.h"

#include "PASER_MSG.h"

/**
 * Implementation of PASER_UU_RREP classes
 */
class PASER_UU_RREP : public PASER_MSG
{
public:
    u_int32_t keyNr;                            ///< Current number of GTK

    uint8_t searchGW;                           ///< search for the gateway
    uint8_t GFlag;                             ///< Gateway flag
    std::list<address_list> AddressRangeList;   ///< Route list from querying node to forwarding node
    uint8_t metricBetweenQueryingAndForw;      ///< Metric for the route between querying node and forwarding node
    uint8_t metricBetweenDestAndForw;          ///< Metric for the route between destination node and forwarding node

    lv_block certForw;                          ///< Certificate of forwarding node
    uint8_t * root;                            ///< Root element of forwarding node
    u_int32_t initVector;                       ///< IV of forwarding node
    geo_pos geoDestination;                     ///< Geographical position of destination node
    geo_pos geoForwarding;                      ///< Geographical position of forwarding node
    kdc_block kdc_data;                         ///< KDC Block
	lv_block sign;                              ///< Signature of the packet
	long timestamp;                             ///< Sending or Forwarding time

	PASER_UU_RREP(const PASER_UU_RREP &m);
	PASER_UU_RREP(struct in_addr src, struct in_addr dest, u_int32_t seqNr);

    static PASER_UU_RREP* create(uint8_t *packet, u_int32_t l);

    ~PASER_UU_RREP();

    PASER_UU_RREP& operator= (const PASER_UU_RREP &m);
    virtual PASER_UU_RREP *dup() const {return new PASER_UU_RREP(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);
    uint8_t * getCompleteByteArray(int *l);
private:
    PASER_UU_RREP();
};

#endif /* PASER_UU_RREP_H_ */
