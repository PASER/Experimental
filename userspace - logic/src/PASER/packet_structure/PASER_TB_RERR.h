/**
 *\class  		PASER_TB_RERR
 *@brief       	Class implements PASER_TB_RERR messages
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

#ifndef PASER_TB_RERR_H_
#define PASER_TB_RERR_H_

#include "../config/PASER_defs.h"

#include <list>
#include <string.h>

#include "PASER_MSG.h"

/**
 * Implementation of PASER_TB_RERR classes
 */
class PASER_TB_RERR : public PASER_MSG
{
public:
    u_int32_t keyNr;                                        ///< Current number of GTK
    std::list<unreachableBlock> UnreachableAdressesList;    ///< List of unreachable addresses

    geo_pos geoForwarding;                                  ///< Geographical position of forwarding node

    uint8_t *secret;                                       ///< Secret of forwarding node
    std::list<uint8_t *> auth;                             ///< Authentication path of forwarding node
    uint8_t *hash;                                         ///< Hash of the packet

    PASER_TB_RERR(const PASER_TB_RERR &m);
    PASER_TB_RERR(struct in_addr src, u_int32_t seqNr);

    static PASER_TB_RERR* create(uint8_t *packet, u_int32_t l);

    ~PASER_TB_RERR();

    PASER_TB_RERR& operator= (const PASER_TB_RERR &m);
    virtual PASER_TB_RERR *dup() const {return new PASER_TB_RERR(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);
    uint8_t * getCompleteByteArray(int *l);
private:
    PASER_TB_RERR();
};

#endif /* PASER_TB_RERR_H_ */
