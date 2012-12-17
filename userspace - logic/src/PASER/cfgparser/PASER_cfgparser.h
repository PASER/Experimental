/**
 *\file  		PASER_cfgparser.h
 *@brief       	Configuration-file-parser for PASER daemon
 *\authors    	Eugen.Paul | Mohamad.Sbeiti | Jan.Schroeder \@paser.info
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



#ifndef PASER_CFG_H
#define	PASER_CFG_H

#include "../syslog/PASER_syslog.h"

/**
 * Convert integer to string
 */
std::string convertInt(int number);

/**
 * Load PASER-configuration-file and initialize paserd_config (struct)
 */
int load_config (std::string filename, PASER_syslog * tmp_log);

/**
 * print PASERd global confs
 */
void print_conf (PASER_syslog * tmp_log);



#endif	/* PASER_CFG_H */

