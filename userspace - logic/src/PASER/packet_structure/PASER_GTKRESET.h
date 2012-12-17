/**
 *\class  		PASER_GTKRESET
 *@brief       	Class implements GTK-reset messages
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

#ifndef GTKRESET_H_
#define GTKRESET_H_

#include <arpa/inet.h>

#include "PASER_MSG.h"
#include "../config/PASER_defs.h"

/**
 * The Class provides functions for GTK-reset
 */
class PASER_GTKRESET:public PASER_MSG {
public:
    u_int32_t keyNr;                ///< Current number of GTK
    lv_block cert;                  ///< Certificate of KDC
    lv_block sign;                  ///< Signature of the packet

public:
    PASER_GTKRESET(const PASER_GTKRESET &m);
    PASER_GTKRESET();
    virtual ~PASER_GTKRESET();

    static PASER_GTKRESET* create(uint8_t *packet, u_int32_t l);

    PASER_GTKRESET& operator= (const PASER_GTKRESET &m);
    virtual PASER_GTKRESET *dup() const {return new PASER_GTKRESET(*this);}
    std::string detailedInfo() const;

    /**
     * Creates and return an array of all fields that must be secured with signature
     *
     *@param l length of created array
     *@return packet array
     */
    uint8_t * toByteArray(int *l);

    /**
     * Creates and return an array of all fields of the package
     *
     *@param l length of created array
     *@return packet array
     */
    uint8_t * getCompleteByteArray(int *l);
};

#endif /* GTKRESET_H_ */
