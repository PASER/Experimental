/**
 *\class  		PASER_scheduler
 *@brief       	Class provides functions for working with PASERs scheduler.
 *@ingroup 		Scheduler
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

class PASER_scheduler;

#ifndef PASERSCHEDULER_H_
#define PASERSCHEDULER_H_

#include "../config/PASER_defs.h"
#include "../config/PASER_global.h"

#include "time.h"

class PASER_scheduler {
private:
    PASER_global *pGlobal;

public:
    PASER_scheduler(PASER_global *paser_global);
    virtual ~PASER_scheduler();

    /**
     * Main scheduler event loop.
     */
    void scheduler();

private:

    /**
     * Process timers. Walk through the timer list and check if
     * any timer is ready to fire.
     */
    void walk_timers();

    /**
     * t1 - t2
     * @param t1
     * @param t2
     * @return
     */
    timeval timeDiff(timeval t1, timeval t2);
};

#endif /* PASERSCHEDULER_H_ */
