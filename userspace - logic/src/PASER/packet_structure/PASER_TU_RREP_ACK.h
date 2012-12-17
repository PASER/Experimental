/**
 *\class  		PASER_TU_RREP_ACK
 *@brief       	Class implements PASER_TU_RREP_ACK messages
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

#ifndef PASER_TU_RREPACK_H_
#define PASER_TU_RREPACK_H_

#include "../config/PASER_defs.h"

#include <list>

#include "PASER_MSG.h"

/**
 * Implementation of PASER_TU_RREPACK classes
 */
class PASER_TU_RREP_ACK : public PASER_MSG
{
public:
    u_int32_t keyNr;                    ///< Current number of GTK
    uint8_t *secret;                   ///< Secret of forwarding node
    std::list<uint8_t *> auth;         ///< Authentication path of forwarding node
	uint8_t *hash;                     ///< Hash of the packet

	PASER_TU_RREP_ACK(const PASER_TU_RREP_ACK &m);
	PASER_TU_RREP_ACK(struct in_addr src, struct in_addr dest, u_int32_t seqNr);

    static PASER_TU_RREP_ACK* create(uint8_t *packet, u_int32_t l);

    ~PASER_TU_RREP_ACK();

    PASER_TU_RREP_ACK& operator= (const PASER_TU_RREP_ACK &m);
    virtual PASER_TU_RREP_ACK *dup() const {return new PASER_TU_RREP_ACK(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);
    uint8_t * getCompleteByteArray(int *l);
private:
    PASER_TU_RREP_ACK();
};

#endif /* PASER_TU_RREPACK_H_ */
