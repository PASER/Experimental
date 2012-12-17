/**
 *\class  		PASER_syslog
 *@brief       	Class provides functions for system logging.
 *
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

#include "PASER_syslog.h"
#include <stdarg.h>

PASER_syslog::PASER_syslog(const char * logFile) {
	log_file = fopen(logFile, "w");
	if (log_file == NULL) {
		std::cout << "ERROR! Cann't open logging file: " << log_file
				<< std::endl;
	}
}

PASER_syslog::PASER_syslog(const char * logFile, bool append) {
	if (append)
		log_file = fopen(logFile, "a");
	else
		log_file = fopen(logFile, "w");
	if (log_file == NULL) {
		std::cout << "ERROR! Cann't open logging file: " << log_file
				<< std::endl;
	}
}

PASER_syslog::~PASER_syslog() {
	if (log_file) {
		fclose(log_file);
	}
}

void PASER_syslog::PASER_log(int level, const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	if (level <= PASER_LOG_LVL) {
		vfprintf(log_file, format, ap);
	}
	va_end(ap);
	fflush(log_file);
}
