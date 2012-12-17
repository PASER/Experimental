/**
 *\class  		KDC_config
 *@brief      	Class implements the Key Distribution Center Configuration
 *
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

#include "KDCconfig.h"

#include "KDCdefs.h"
#include <string.h>

KDC_config::KDC_config() {
    certfile = new char[strlen(PASER_kdc_cert_file) + 1];
    strcpy(certfile, PASER_kdc_cert_file);

    keyfile = new char[strlen(PASER_kdc_cert_key_file) + 1];
    strcpy(keyfile, PASER_kdc_cert_key_file);

    cafile = new char[strlen(PASER_kdc_CA_cert_file) + 1];
    strcpy(cafile, PASER_kdc_CA_cert_file);

    crlfile = new char[strlen(PASER_kdc_CRL_file) + 1];
    strcpy(crlfile, PASER_kdc_CRL_file);

    logFile = new char[strlen(KDC_log_file) + 1];
    strcpy(logFile, KDC_log_file);
}

KDC_config::KDC_config(struct paserd_conf *configData) {
    certfile = new char[strlen(PASER_kdc_cert_file) + 1];
    strcpy(certfile, PASER_kdc_cert_file);

    keyfile = new char[strlen(PASER_kdc_cert_key_file) + 1];
    strcpy(keyfile, PASER_kdc_cert_key_file);

    cafile = new char[strlen(PASER_kdc_CA_cert_file) + 1];
    strcpy(cafile, PASER_kdc_CA_cert_file);

    crlfile = new char[strlen(PASER_kdc_CRL_file) + 1];
    strcpy(crlfile, PASER_kdc_CRL_file);

    logFile = new char[configData->logFile.length() + 1];
    strcpy(logFile, configData->logFile.c_str());
//    logFile = new char[strlen(KDC_log_file) + 1];
//    strcpy(logFile, KDC_log_file);
}

KDC_config::~KDC_config() {
    delete[] certfile;
    delete[] keyfile;
    delete[] cafile;
    delete[] crlfile;
    delete[] logFile;
}

