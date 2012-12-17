/**
 *\class  		PASER_timer_queue
 *@brief       	Class provides a list of node's timer.
 *@ingroup 		TM
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

#ifndef PASER_TIMER_QUEUE_H_
#define PASER_TIMER_QUEUE_H_

#include "PASER_timer_packet.h"
#include <list>

#include <sstream>
#include <stdlib.h>
#include <string.h>

class PASER_timer_queue{
public:
    /**
     * List of node's timer.
     */
	std::list<PASER_timer_packet *> timer_queue;

public:
	~PASER_timer_queue();

	void init();

	/**
	 * Sort the list by time
	 */
	void timer_sort();

	/**
	 * Add a new timer timer to the queue (lower to higher timeout order)
	 */
	int timer_add(PASER_timer_packet *t);

	/**
	 * Remove a timer from the queue
	 */
	int timer_remove(PASER_timer_packet *t);

	/**
	 * This Function return next Timeout
	 */
	PASER_timer_packet *timer_get_next_timer();

	/**
	 * Get time difference
	 *
	 *@param t1 Pointer to timer
	 *@param t2 Pointer to timer
	 *
	 *@return t1 - t2
	 */
	long timeval_diff(struct timeval *t1, struct timeval *t2);

	/**
	 * Get size of timer list
	 */
	int getTimerQueueSize(){return timer_queue.size();};

	std::ostream& operator<<(std::ostream& os)
	{
	    os << "timer_queue.size: \n" ;
	    return os;
	};

    std::string shortInfo();
    std::string detailedInfo();
};

#endif /* PASER_TIMER_QUEUE_H_ */
