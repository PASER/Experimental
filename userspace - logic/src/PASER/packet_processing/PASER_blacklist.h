/**
 *\class  		PASER_blacklist
 *@brief       	Class provides a map of IP addresses to which a route was broken and a RERR message was sent.
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

class PASER_blacklist;

#ifndef PASER_BLACKLIST_H_
#define PASER_BLACKLIST_H_

#include "../config/PASER_defs.h"

#include <map>
#include <sstream>
#include <stdlib.h>
#include <string.h>

/**
 * Implementation of PASER_config classes.
 */
class PASER_blacklist {
private:
    /**
     * Map of IP addresses.
     * Key   - IP Address
     * Value - Time when a RERR message was send
     */
    std::map<Uint128, struct timeval> rerr_list;
public:
    /**
     * Add or edit an entry in container
     *
     *@param addr IP Address
     *@param time Timestamp
     *
     *@return true on successful or false if an entry has been added/edited
     *in the last <b>PASER_TB_RERR_limit</b> seconds.
     */
    bool setRerrTime(struct in_addr addr, struct timeval time);

    /**
     * delete all entries in container
     */
    void clearRerrList();

    int getSize(){return rerr_list.size();}
    std::string detailedInfo();
};

#endif /* PASER_BLACKLIST_H_ */
