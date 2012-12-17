/**
 *\file  		main.cpp
 *@brief       	main.cpp is responsible for starting the PASER daemon.
 *@ingroup		Configuration
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

/**
 *\mainpage 	PASER Documentation
 *\section     	Overview This page provides a thorough documentation of the PASER implementation in Linux.
 *\authors     	Eugen.Paul | Mohamad.Sbeiti \@paser.info
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

/**
 *  @defgroup Configuration Configuration
 *  @defgroup Cryptography Cryptography
 *  @defgroup KDC Key Distribution Center
 *  @defgroup PP Packet Processing
 *  @defgroup PS Packet Structure
 *  @defgroup RD Route Discovery
 *  @defgroup RM Route Maintenance
 *  @defgroup GPS GPS Reader
 *  @defgroup Scheduler Scheduler
 *  @defgroup Socket Socket
 *  @defgroup Statistics Statistics
 *  @defgroup Syslog System-Logging
 *  @defgroup Tables Tables
 *  @defgroup TM Timer Management
 */

#include <iostream>
#include <cstdlib>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <libconfig.h++>

#include "defs.h"
//#include "src/logger/logger.h"
//#include "src/cfgparser/cfgparser.h"
#include "src/PASER/cfgparser/PASER_cfgparser.h"

#include "src/PASER/config/PASER_defs.h"
#include "src/PASER/config/PASER_config.h"
#include "src/PASER/config/PASER_global.h"
#include "src/KDC/config/KDCconfig.h"
#include "src/KDC/scheduler/KDCscheduler.h"

#include "src/PASER/syslog/PASER_syslog.h"

#include <sys/stat.h>

using namespace libconfig;
using namespace std;

paserd_conf conf;
bool isRunning = true;

void signal_handler(int sig) {
	switch (sig) {
	case SIGHUP:
		std::cout << "PASERd: SIGHUP catched" << endl;
		//load_config(PASERD_GLOBAL_CONF_FILE, Syslog);
		//if (atoi(conf.debuglevel.c_str()))
		//	print_conf(Syslog);
		break;
	case SIGTERM:
		std::cout << "PASERd: SIGTERM catched" << endl;
		isRunning = false;
//        exit(0);
		break;
	}
}

void daemonize() {
	int i;
	FILE * lock_file;

	if (getppid() == 1)
		return; // already a daemon

	i = fork();
	if (i < 0)
		exit(1); // fork error
	if (i > 0)
		exit(0); // parent exits
	// child (daemon) continues

	setsid(); // obtain a new process group

	for (i = getdtablesize() - 1; i >= 0; --i)
		close(i); // close all descriptors

	i = open("/dev/null", O_RDWR);
	dup(i);
	dup(i); // handle standard I/O

	umask(027); // set newly created file permissions
	chdir(RUNNING_DIR); // change running directory

	if (conf.isKDCdeamon) {
		lock_file = fopen(LOCK_KDC_FILE, "w");
	} else {
		lock_file = fopen(LOCK_FILE, "w");
	}

	if (lock_file == NULL) {
		std::cout << "ERROR: Can't open lock_file " << LOCK_FILE << endl;
	}

	// write PID to lock_file
	fprintf(lock_file, "%d\n", getpid());
	fclose(lock_file);

	signal(SIGCHLD, SIG_IGN ); // ignore child
	signal(SIGTSTP, SIG_IGN ); // ignore tty signals
	signal(SIGTTOU, SIG_IGN );
	signal(SIGTTIN, SIG_IGN );
	signal(SIGHUP, signal_handler); // catch hangup signal
	signal(SIGTERM, signal_handler); // catch kill signal
}

void start_paser(PASER_syslog* Syslog) {
	// initialize and start PASER
	PASER_config * pConfig;
	PASER_global *pGlobal;
	// initialize random seed:
	srand(time(NULL));

	if (conf.isKDCdeamon) {
		KDC_config *kdc_conf = new KDC_config(&conf);
		KDC_scheduler *kdc_sch = new KDC_scheduler(kdc_conf);
		kdc_sch->scheduler();
		delete kdc_sch;
		delete kdc_conf;
	} else if (conf.IsGateway) {
		pConfig = new PASER_config(&conf);
		pGlobal = new PASER_global(pConfig, Syslog);
		lv_block cert;
		if (!pGlobal->getCrypto_sign()->getCert(&cert)) {
			PASER_LOG_WRITE_LOG(PASER_LOG_ERROR,
					"ERROR! Cann't load own certificate.\n");
			exit(1);
		}
		// generate random nonce
		pGlobal->generateGwSearchNonce();
		//generate and send KDC Request
		pGlobal->getPacketSender()->sendKDCRequest(DEV_NR(0).ipaddr, DEV_NR(0).ipaddr,cert, pGlobal->getLastGwSearchNonce());
		free(cert.buf);

		// set KDC request timeout
		PASER_timer_packet *timePacket = new PASER_timer_packet();
		struct timeval now;
		pGlobal->getPASERtimeofday(&now);
		timePacket->handler = KDC_REQUEST;
		timePacket->timeout = timeval_add(now, PASER_KDC_REQUEST_TIME);
		timePacket->destAddr =
				pGlobal->getPaser_configuration()->getAddressOfKDC();
		pGlobal->getTimer_queue()->timer_add(timePacket);

		// start main scheduler
		pGlobal->getScheduler()->scheduler();
		delete pGlobal;
		delete pConfig;
	} else {
		pConfig = new PASER_config(&conf);
		pGlobal = new PASER_global(pConfig, Syslog);
		// send register message
		pGlobal->getRoute_findung()->tryToRegister();
		// start main scheduler
		pGlobal->getScheduler()->scheduler();
		delete pGlobal;
		delete pConfig;
	}
}

int main(int argc, char *argv[]) {
	int KDC_flag = 0;
	char *cvalue = NULL;
	int c;
	int length = 0;
	isRunning = true;

	while ((c = getopt(argc, argv, "r:")) != -1) {
		switch (c) {
		case 'r':
			std::cout << "Role Flag is set\n";
			cvalue = optarg;
			length = strlen(cvalue);
			if (length == 3 && !memcmp(cvalue, "KDC", 3)) {
				KDC_flag = 1;
			} else {
				fprintf(stderr, "Unknown argument \"%s\"\n", optarg);
				exit(1);
			}
			break;
		case '?':
			if (optopt == 'r')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			break;
		default:
			break;
		}
	}

	// initialize OPENSSL
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();

	if (KDC_flag) {
		conf.isKDCdeamon = true;
		conf.logFile = KDCD_GLOBAL_LOG_FILE;
	} else {
		conf.isKDCdeamon = false;
		conf.logFile = PASERD_GLOBAL_LOG_FILE;
	}

	PASER_syslog *Syslog;
	Syslog = new PASER_syslog(conf.logFile.c_str());

	load_config(PASERD_GLOBAL_CONF_FILE, Syslog);

//	if (atoi(conf.debuglevel.c_str()))
		print_conf(Syslog);

	delete Syslog;
	daemonize();
	Syslog = new PASER_syslog(conf.logFile.c_str(), true);
	start_paser(Syslog);

	ENGINE_cleanup();
	ERR_free_strings();
	EVP_cleanup();
}

/* EOF */
