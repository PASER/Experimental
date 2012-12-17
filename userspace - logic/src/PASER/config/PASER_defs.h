/**
 *\file  		PASER_defs.h
 *@brief		File defines all relevant attributes for the PASER daemon
 *@ingroup		Configuration
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

#ifndef PASER_DEFS_H_
#define PASER_DEFS_H_

//#define PASER_MODULE_TEST
#define PASER_SOCKET_TEST

#include <boost/asio.hpp>
#define _LINUX_IF_H

#include "openssl/ssl.h"
#include <iostream>
#include <math.h>
//#define ev std::cout
//#define EV std::cout

#define Uint128 uint32_t
#define u_int8_t uint8_t

#define opp_error //
#include <arpa/inet.h>

#include <list>

#include "../../../defs.h"

// logging parameters
//#define PASER_LOG_LVL 5
//#define PASER_LOG_CONFIGURATION 1
//#define PASER_LOG_SCHEDULER 3
//#define PASER_LOG_INIT_MODULES 1
//#define PASER_LOG_INVALID_PACKET 2
//#define PASER_LOG_ROUTE_DISCOVERY 2
//#define PASER_LOG_PACKET_PROCESSING 2
//#define PASER_LOG_ROUTING_TABLE 2
//#define PASER_LOG_PACKET_INFO 5
//#define PASER_LOG_TIMEOUT_INFO 3
//#define PASER_LOG_CRYPTO_ERROR 2
//#define PASER_LOG_ERROR 1
//#define PASER_LOG_CONNECTION 1
extern paserd_conf conf;

#define PASER_LOG_LVL               conf.LOG_LVL
#define PASER_LOG_CONFIGURATION     conf.LOG_CONFIGURATION
#define PASER_LOG_SCHEDULER         conf.LOG_SCHEDULER
#define PASER_LOG_INIT_MODULES      conf.LOG_INIT_MODULES
#define PASER_LOG_INVALID_PACKET    conf.LOG_INVALID_PACKET
#define PASER_LOG_ROUTE_DISCOVERY   conf.LOG_ROUTE_DISCOVERY
#define PASER_LOG_PACKET_PROCESSING conf.LOG_PACKET_PROCESSING
#define PASER_LOG_ROUTING_TABLE     conf.LOG_ROUTING_TABLE
#define PASER_LOG_PACKET_INFO       conf.LOG_PACKET_INFO
#define PASER_LOG_TIMEOUT_INFO      conf.LOG_TIMEOUT_INFO
#define PASER_LOG_CRYPTO_ERROR      conf.LOG_CRYPTO_ERROR
#define PASER_LOG_ERROR             conf.LOG_ERROR
#define PASER_LOG_CONNECTION        conf.LOG_CONNECTION

#define PASER_LOG_ROUTE_MODIFICATION_ADD conf.LOG_ROUTE_MODIFICATION_ADD
#define PASER_LOG_ROUTE_MODIFICATION_DELETE conf.LOG_ROUTE_MODIFICATION_DELETE
#define PASER_LOG_ROUTE_MODIFICATION_BREAK conf.LOG_ROUTE_MODIFICATION_BREAK
#define PASER_LOG_ROUTE_MODIFICATION_TIMEOUT conf.LOG_ROUTE_MODIFICATION_TIMEOUT

#define PASER_LOG_FILE      "log.log"

#define PASER_LOG_WRITE_LOG_SHORT(LVL, FMT, ...) pGlobal->getSyslog()->PASER_log(LVL, FMT, ##__VA_ARGS__);
#define PASER_LOG_WRITE_LOG(LVL, FMT, ...) pGlobal->getSyslog()->PASER_log(LVL, "[%s at %s:%u]: " FMT, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__);
#define PASER_LOG_GET_FD pGlobal->getSyslog()->getLog_file()

/// Returns a dev_info struct given its corresponding device number
#define DEV_NR(n) (pGlobal->getPaser_configuration()->getNetDevice()[n])
#define ETHDEV_NR(n) (pGlobal->getPaser_configuration()->getNetEthDevice()[n])

/// Port number on which PASER packages will be send
//#define PASER_PORT 1653
#define PASER_PORT      conf.port
/// Port number of KDC Server
//#define PASER_PORT_KDC 1654
#define PASER_PORT_KDC  conf.KDCPort

#define PASER_PATH_TO_PASER_FILES "/etc/PASER/"
/// Path to PASER Router certificate
#define PASER_cert_file        PASER_PATH_TO_PASER_FILES "cert/router.pem"
/// Path to PASER Router private key
#define PASER_cert_key_file    PASER_PATH_TO_PASER_FILES "cert/router.key"
/// Path to PASER gateway certificate
#define PASER_gw_cert_file     PASER_PATH_TO_PASER_FILES "cert/gateway.pem"
/// Path to PASER gateway private key
#define PASER_gw_cert_key_file PASER_PATH_TO_PASER_FILES "cert/gateway.key"
/// Path to PASER CA certificate
#define PASER_CA_cert_file     PASER_PATH_TO_PASER_FILES "cert/cacert.pem"

#define PASERD_ROUTE_ADD_LOG_FILE PASER_PATH_TO_PASER_FILES "log_route_add.txt"
#define PASERD_ROUTE_DELETE_LOG_FILE PASER_PATH_TO_PASER_FILES "log_route_delete.txt"
#define PASERD_ROUTE_BREAK_LOG_FILE PASER_PATH_TO_PASER_FILES "log_route_break.txt"
#define PASERD_ROUTE_TIMEOUT_LOG_FILE PASER_PATH_TO_PASER_FILES "log_route_timeout.txt"

#define PASERD_OVERHEAD_LOG_FILE PASER_PATH_TO_PASER_FILES "log_overhead.txt"

/// Maximum length of the PASER signature
#define PASER_sign_len 4096

/// Maximum transmitting range of wireless card
#define PASER_radius conf.GPS_MAX_NEIGHBOR_DISTANCE

/// Active route timeouts (s)
#define PASER_ROUTE_DELETE_TIME conf.PASER_CONF_ROUTE_DELETE_TIMEOUT
#define PASER_ROUTE_VALID_TIME conf.PASER_CONF_ROUTE_VALID_TIMEOUT
#define PASER_NEIGHBOR_DELETE_TIME conf.PASER_CONF_NEIGHBOR_DELETE_TIMEOUT
#define PASER_NEIGHBOR_VALID_TIME conf.PASER_CONF_NEIGHBOR_VALID_TIMEOUT
//#define PASER_ROUTE_DELETE_TIME 90.0
//#define PASER_ROUTE_VALID_TIME 80.0
//#define PASER_NEIGHBOR_DELETE_TIME 90.0
//#define PASER_NEIGHBOR_VALID_TIME 80.0
//#define PASER_ROUTE_DELETE_TIME 21.0
//#define PASER_ROUTE_VALID_TIME 6.0
//#define PASER_NEIGHBOR_DELETE_TIME 20.0
//#define PASER_NEIGHBOR_VALID_TIME 5.0

/// Hello sending interval (s)
#define PASER_TB_HELLO_Interval conf.PASER_CONF_TB_HELLO_Interval
//#define PASER_TB_HELLO_Interval 2.0

/// Max wait time for a route request response (s)
#define PASER_UB_RREQ_WAIT_TIME conf.PASER_CONF_UB_RREQ_WAIT_TIME
/// Max wait time for a route request replay (s)
#define PASER_UU_RREP_WAIT_TIME conf.PASER_CONF_UU_RREP_WAIT_TIME

/// RREQ retries before fail and sending unreachable
#define PASER_UB_RREQ_TRIES conf.PASER_CONF_UB_RREQ_TRIES
/// RREP retries before fail
#define PASER_UU_RREP_TRIES conf.PASER_CONF_UU_RREP_TRIES

/// Max wait time for a KDC request replay (s)
#define PASER_KDC_REQUEST_TIME conf.PASER_CONF_KDC_REQUEST_TIME

/// Delay between sending buffered packets (ms)
#define PASER_DATA_PACKET_SEND_DELAY 0.0

/// Length of PASER Secret
#define PASER_SECRET_LEN 32
/// Length of PASER SECRET HASH. MUST BE 32 (SHA256_DIGEST_LENGTH)
#define PASER_SECRET_HASH_LEN 32
/// Number of generated secrets 2^secret_parameter
#define PASER_root_param conf.PASER_NUMBER_OF_SECRETS
/// Max wait time for a new root broadcast replay
#define PASER_root_repeat_timeout 1.0
/// Number of new root broadcast repetitions
#define PASER_root_repeat 2

/// Broadcast address (255.255.255.255)
#define PASER_BROADCAST ((in_addr_t) 0xFFFFFFFF)

/// ALLONES_ADDRESS MASK (255.255.255.255)
#define PASER_ALLONES_ADDRESS_MASK ((in_addr_t) 0xFFFFFFFF)

#define PASER_SUBNETWORK ((in_addr_t) 0x0A000100)
#define PASER_MASK ((in_addr_t) 0xFFFF0000)

/// Allowed time difference by incoming untrusted packets (s)
//#define PASER_time_diff 120
#define PASER_time_diff     conf.timeDiff

/// How often a RERR message to the same IP address will be sent(ms)
#define PASER_TB_RERR_limit 500

/// Maximum sequence number
#define PASER_MAXSEQ ((u_int32_t)0xFFFFFFFF)

/// TTL field in IP header for every PASER packet
#define PASER_IPTTL 1

typedef struct {
    double lat;
    double lon;
} geo_pos;

typedef struct {
    in_addr addr;
    u_int32_t seq;
} unreachableBlock;

typedef struct {
    uint8_t *buf;
    int32_t len;
} lv_block;

typedef struct {
    lv_block GTK;
    u_int32_t nonce;
    lv_block CRL;
    lv_block cert_kdc;
    lv_block sign;
    u_int32_t key_nr;
    lv_block sign_key;
} kdc_block;

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif  /* IFNAMSIZ */

/*
 *A struct containing all necessary information about each
 *interface participating in the PASER routing
 */
typedef struct {
    int enabled; /* 1 if struct is used, else 0 */
    int sock; /* PASER socket associated with this device */
    int icmp_sock; /* Raw socket used to send/receive ICMP messages */
    u_int32_t ifindex; /* Index for this interface */
    char ifname[IFNAMSIZ]; /* Interface name */
    struct in_addr ipaddr; /* The local IP address */
    struct in_addr bcast; /* Broadcast address */
    struct in_addr mask; /* Mask */
} network_device;

struct address_range {
    struct in_addr ipaddr; /* The IP address */
    struct in_addr mask; /* mask */

    address_range() {
        ipaddr.s_addr = (Uint128) 0;
        mask.s_addr = (Uint128) 0;
    }
    address_range & operator =(const address_range &other) {
        if (this == &other)
            return *this;
        ipaddr = other.ipaddr;
        mask = other.mask;
        return *this;
    }
};

struct address_list {
    struct in_addr ipaddr; /* The IP address */
    std::list<address_range> range; /* List of the node's subnetworks */

    address_list() {
        ipaddr.s_addr = (Uint128) 0;
    }
    address_list & operator =(const address_list &other) {
        if (this == &other)
            return *this;
        ipaddr = other.ipaddr;
        range.assign(other.range.begin(), other.range.end());
        return *this;
    }
};

inline timeval timeval_add(const timeval a, double b) {
    double bInt;
    double bFrac = modf(b, &bInt);
    timeval res;
    res.tv_sec = a.tv_sec + (long) bInt;
    res.tv_usec = a.tv_usec + (long) floor(1000000.0 * bFrac);
    if (res.tv_usec > 1000000) {
        res.tv_sec++;
        res.tv_usec -= 1000000;
    }
    return res;
}


#endif /* PASER_DEFS_H_ */
