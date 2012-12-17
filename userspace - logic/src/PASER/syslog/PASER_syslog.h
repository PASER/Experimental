/**
 *\class  		PASER_syslog
 *@brief       	Class provides functions for system logging.
 *@ingroup 		Syslog
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

class PASER_syslog;

#ifndef PASER_syslog_H_
#define PASER_syslog_H_

#include "../config/PASER_defs.h"
#include <stdio.h>

class PASER_syslog {
private:
    FILE * log_file;

public:
    PASER_syslog(const char * logFile);
    PASER_syslog(const char * logFile, bool append);
    ~PASER_syslog();

    /**
     * Write to log file
     */
    void PASER_log(int level, const char *format, ...) __attribute__ ((format(printf, 3, 4)));

    FILE *getLog_file(){return log_file;}

private:
    /**
     * Open debug file
     */
    void PASER_openlog(const char *ident);
};

#endif /* PASER_syslog_H_ */
