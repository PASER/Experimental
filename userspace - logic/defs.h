/**
 *\file  		defs.h
 *@brief       	file defines configuration-parameters of the PASER daemon
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

#ifndef DEFS_H
#define DEFS_H

#define VERSION 0.1     

#define PASERD_CONF_FILENAME	"paserd.conf"
#define PASERD_GLOBAL_CONF_FILE	"/etc/PASER/" PASERD_CONF_FILENAME

#define PASERD_LOG_FILENAME    "paserd_global.log"
#define KDCD_LOG_FILENAME    "kdcd_global.log"
#define PASERD_GLOBAL_LOG_FILE  "/var/log/" PASERD_LOG_FILENAME
#define KDCD_GLOBAL_LOG_FILE  "/var/log/" KDCD_LOG_FILENAME

#define RUNNING_DIR	"/tmp"
#define LOCK_FILE	"paserd.lock"
#define LOCK_KDC_FILE	"kdcd.lock"

#include <vector>
#include <errno.h>
#include <string>

struct __plugin_param {
    std::string key;
    std::string value;
};

struct __plugin_entry {
    std::string name;
    std::vector<__plugin_param> params;
};

struct __interface {
    std::string name;
    std::string IPv4_addr;
    std::string IPv4_mask;
};

/*
 * The main configuration struct-container of the PASER daemon
 */
struct paserd_conf {
    int pid;
    std::string IPversion;
    int port;
    int KDCPort;
    std::string KDCIPAddress;
    std::string logFile;
    bool IsGateway;
    bool isKDCdeamon;

    int LOG_LVL;
    int LOG_CONFIGURATION;
    int LOG_SCHEDULER;
    int LOG_INIT_MODULES;
    int LOG_INVALID_PACKET;
    int LOG_ROUTE_DISCOVERY;
    int LOG_PACKET_PROCESSING;
    int LOG_ROUTING_TABLE;
    int LOG_PACKET_INFO;
    bool LOG_PACKET_INFO_FULL;
    int LOG_TIMEOUT_INFO;
    int LOG_CRYPTO_ERROR;
    int LOG_ERROR;
    int LOG_CONNECTION;

    int LOG_ROUTE_MODIFICATION_ADD;
    int LOG_ROUTE_MODIFICATION_DELETE;
    int LOG_ROUTE_MODIFICATION_BREAK;
    int LOG_ROUTE_MODIFICATION_TIMEOUT;

    int PASER_radius;
    int PASER_NUMBER_OF_SECRETS;

    double PASER_CONF_ROUTE_DELETE_TIMEOUT;
    double PASER_CONF_ROUTE_VALID_TIMEOUT;
    double PASER_CONF_NEIGHBOR_DELETE_TIMEOUT;
    double PASER_CONF_NEIGHBOR_VALID_TIMEOUT;
    double PASER_CONF_TB_HELLO_Interval;
    double PASER_CONF_UB_RREQ_WAIT_TIME;
    double PASER_CONF_UU_RREP_WAIT_TIME;
    double PASER_CONF_UB_RREQ_TRIES;
    double PASER_CONF_UU_RREP_TRIES;
    double PASER_CONF_KDC_REQUEST_TIME;

    int timeDiff;

    int GPS_ENABLE;
    std::string GPS_SERIAL_PORT;
    int GPS_SERIAL_SPEED;
    double GPS_MAX_NEIGHBOR_DISTANCE;
    double GPS_STATIC_LAT;
    double GPS_STATIC_LON;
    double GPS_STATIC_ALT;

    std::vector<__interface> interface;
    std::vector<__interface> interfaceSubnetwork;
    std::vector<__plugin_entry> plugins;
};

#endif	/* DEFS_H */

