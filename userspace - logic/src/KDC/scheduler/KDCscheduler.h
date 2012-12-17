/**
 *\class  		KDC_scheduler
 *@brief		Class implements the KDC's scheduler
 *@ingroup		KDC
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

class KDC_scheduler;

#ifndef KDCSCHEDULER_H_
#define KDCSCHEDULER_H_

#include "../../PASER/config/PASER_defs.h"
#include "../../PASER/syslog/PASER_syslog.h"
#include "../config/KDCdefs.h"
#include "../config/KDCconfig.h"
#include "../crypto/KDCcryptosign.h"
#include "KDCsocket.h"

extern bool isRunning;

class KDC_scheduler {
private:
    KDC_socket *socket;
    PASER_syslog *log;
    KDC_crypto_sign *crypto;
    KDC_config * config;
public:
    KDC_scheduler(KDC_config *KDC_config);
    virtual ~KDC_scheduler();

    /**
     * Main scheduler event loop.
     */
    void scheduler();

private:
    /**
     * Process data on incoming file descriptor
     * @param fd file descriptor
     */
    void processData(int fd);
};

#endif /* KDCSCHEDULER_H_ */
