/**
 *\class  		PASER_config
 *@brief       	Class implements the PASER_config classes.
 *@ingroup		Configuration
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

class PASER_config;

#ifndef PASER_CONFIG_H_
#define PASER_CONFIG_H_

#include "PASER_defs.h"
#include "../../../defs.h"

/**
 * This class loads PASER Configuration and provides a space for the PASER configuration and settings.
 */
class PASER_config {
public:
    /**
     * Constructor
     *
     */
//    PASER_config(char *configFile);
    PASER_config(struct paserd_conf *configData);
    ~PASER_config();

    bool getIsGW();

    char *getCertfile();
    char *getKeyfile();
    char *getCAfile();

    char *getLog();

    bool isGWsearch();

    u_int32_t getRootRepetitionsTimeout();
    u_int32_t getRootRepetitions();

    u_int32_t getNetEthDeviceNumber();
    network_device *getNetEthDevice();
    u_int32_t getNetDeviceNumber();
    network_device *getNetDevice();
    u_int32_t getNetAddDeviceNumber();
    network_device *getNetAddDevice();
    struct in_addr getAddressOfKDC();

    int getLOG_LVL();
    int getLOG_CONFIGURATION();
    int getLOG_SCHEDULER();
    int getLOG_INIT_MODULES();
    int getLOG_INVALID_PACKET();
    int getLOG_ROUTE_DISCOVERY();
    int getLOG_PACKET_PROCESSING();
    int getLOG_ROUTING_TABLE();
    int getLOG_PACKET_INFO();
    int getLOG_TIMEOUT_INFO();
    int getLOG_CRYPTO_ERROR();
    int getLOG_ERROR();
    int getLOG_CONNECTION();

    bool isResetHelloByBroadcast();

    bool isLinkLayerFeeback();

    bool isLocalRepair();
    int getMaxLocalRepairHopCount();

    /**
     * Check if the entered address <b>Addr</b> in the own subnetworks is
     *
     *@param Addr IP address that will be checked
     */
    bool isAddInMySubnetwork(struct in_addr Addr);

    /**
     * Check if the entered address <b>Addr</b> the own IP address is
     *
     *@param Addr IP address that will be checked
     */
    bool isAddInMyLocalAddress(struct in_addr Addr);

    int getIfIdFromIfIndex(uint32_t ifIndex);
    int getIfIdFromAddress(in_addr ip);

    std::list<address_range> getAddL();     ///< Address List of node's subnetworks
private:
    bool isGW;                              ///< is the Node a Gateway
    char *certfile, *keyfile, *cafile;      ///< Path to Node's Certificate, Key and CA File
    char *logfile;                          ///< Path to log file

    u_int32_t netEthDeviceNumber;           ///< Number of Ethernet cards
    u_int32_t netDeviceNumber;              ///< Number of wireless cards on which PASER is running
    u_int32_t netAddDeviceNumber;           ///< Number of subnetworks

    network_device *netEthDevice;           ///< Array of Ethernet cards
    network_device *netDevice;              ///< Array of wireless cards on which PASER is running
    network_device *netAddDevice;           ///< Array of subnetworks

    u_int32_t root_repetitions_timeout;     ///< Root sending interval
    u_int32_t root_repetitions;             ///< Number of same Root repetition

    struct in_addr addressOfKDC;            ///< Address of KDC

    bool setGWsearch;                       ///< enable proactive search for the gateway
    bool LinkLayerFeeback;                  ///< enable link layer feedback

    bool LocalRepair;                       ///< enable Local Repair
    u_int32_t maxHopCountForLocalRepair;    ///< maximum number of hops to the node to which the Route will be repaired

    std::list<address_range> AddL;          ///< Address List of node's subnetworks

    bool resetHelloByBroadcast;

    int LOG_LVL;
    int LOG_CONFIGURATION;
    int LOG_SCHEDULER;
    int LOG_INIT_MODULES;
    int LOG_INVALID_PACKET;
    int LOG_ROUTE_DISCOVERY;
    int LOG_PACKET_PROCESSING;
    int LOG_ROUTING_TABLE;
    int LOG_PACKET_INFO;
    int LOG_TIMEOUT_INFO;
    int LOG_CRYPTO_ERROR;
    int LOG_ERROR;
    int LOG_CONNECTION;

    /**
     * Initialize the Array of node's subnetworks
     */
    void intAddlList();
};

#endif /* PASER_CONFIG_H_ */
