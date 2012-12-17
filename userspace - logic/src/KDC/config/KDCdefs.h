/**
 *\file  		KDCdefs.h
 *@brief       	Key Distribution Center Definitions
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

#ifndef KDCDEFS_H_
#define KDCDEFS_H_

#include "../../PASER/config/PASER_defs.h"

#define KDC_LOG_PACKET_INFO 5

#define KDC_LOG_WRITE_LOG_SHORT(LVL, FMT, ...) log->PASER_log(LVL, FMT, ##__VA_ARGS__);
#define KDC_LOG_WRITE_LOG(LVL, FMT, ...) log->PASER_log(LVL, "[%s at %s:%u]: " FMT, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__);
#define KDC_LOG_GET_FD log->getLog_file()

/// Path to KDC logfile
#define KDC_log_file PASER_PATH_TO_PASER_FILES "KDC_log.log"

/// Path to KDC certificate
#define PASER_kdc_cert_file     PASER_PATH_TO_PASER_FILES "cert/kdccert.pem"
/// Path to KDC private key
#define PASER_kdc_cert_key_file PASER_PATH_TO_PASER_FILES "cert/kdckey.key"
/// Path to PASER CA certificate
#define PASER_kdc_CA_cert_file  PASER_PATH_TO_PASER_FILES "cert/cacert.pem"
/// Path to CRL
#define PASER_kdc_CRL_file      PASER_PATH_TO_PASER_FILES "cert/crl.pem"

#endif /* KDCDEFS_H_ */
