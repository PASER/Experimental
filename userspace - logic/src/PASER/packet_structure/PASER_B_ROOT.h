/**
 *\class  		PASER_B_ROOT
 *@brief       	Class implements PASER_B_ROOT messages
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

class PASER_B_ROOT;

#ifndef PASER_B_ROOT_H_
#define PASER_B_ROOT_H_


#include <list>
#include <string.h>

#include "../config/PASER_defs.h"
#include "PASER_MSG.h"

/**
 * Implementation of the PASER_B_ROOT classes
 */
class PASER_B_ROOT : public PASER_MSG{
public:
    long timestamp;             ///< Sending time

    lv_block cert;              ///< Certificate of sending node
    uint8_t * root;             ///< The root element of sending node
    u_int32_t initVector;       ///< IV of sending or forwarding node
    geo_pos geoQuerying;        ///< Geographical position of sending node
    lv_block sign;              ///< Signature of the packet

    PASER_B_ROOT(const PASER_B_ROOT &m);
    PASER_B_ROOT(struct in_addr src, u_int32_t seqNr);

    static PASER_B_ROOT* create(uint8_t *packet, u_int32_t l);

    virtual ~PASER_B_ROOT();

    PASER_B_ROOT& operator= (const PASER_B_ROOT &m);
    virtual PASER_B_ROOT *dup() const {return new PASER_B_ROOT(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);
    uint8_t * getCompleteByteArray(int *l);

private:
    PASER_B_ROOT();
};

#endif /* PASER_B_ROOT_H_ */
