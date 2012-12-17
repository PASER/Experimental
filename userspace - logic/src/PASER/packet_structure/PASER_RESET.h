/**
 *\class  		PASER_RESET
 *@brief       	Class implements PASER_RESET messages
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


#ifndef PASER_RESET_H_
#define PASER_RESET_H_

#include "../config/PASER_defs.h"
#include "PASER_MSG.h"

#include <list>
#include <string.h>


/**
 * Implementation of PASER_RESET classes
 */
class PASER_RESET : public PASER_MSG
{
public:
    u_int32_t keyNr;    ///< Current number of GTK
    lv_block cert;      ///< Certificate of KDC
    lv_block sign;      ///< Signature of the packet

    PASER_RESET(const PASER_RESET &m);
    PASER_RESET(struct in_addr src);

    static PASER_RESET* create(uint8_t *packet, u_int32_t l);

    ~PASER_RESET();

    PASER_RESET& operator= (const PASER_RESET &m);
    virtual PASER_RESET *dup() const {return new PASER_RESET(*this);}
    std::string detailedInfo() const;

    uint8_t * toByteArray(int *l);
    uint8_t * getCompleteByteArray(int *l);
private:
    PASER_RESET();
};

#endif /* PASER_RESET_H_ */
