/**
 *\class  		PASER_config
 *@brief       	Class implements the PASER_config classes.
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

#include "PASER_config.h"

#include <string.h>

//PASER_config::PASER_config(char *configFile) {
//    resetHelloByBroadcast = false;
//    LOG_LVL = 5;
//    LOG_CONFIGURATION = 1;
//    LOG_SCHEDULER = 3;
//    LOG_INIT_MODULES = 1;
//    LOG_INVALID_PACKET = 2;
//    LOG_ROUTE_DISCOVERY = 2;
//    LOG_PACKET_PROCESSING = 2;
//    LOG_ROUTING_TABLE = 2;
//    LOG_PACKET_INFO = 5;
//    LOG_TIMEOUT_INFO = 3;
//    LOG_CRYPTO_ERROR = 2;
//    LOG_ERROR = 1;
//    LOG_CONNECTION = 1;
//
//#ifdef PASER_MODULE_TEST
//    if (configFile[0] == 'P') {
//        isGW = true;
//    } else {
//        isGW = false;
//    }
//
//    if (isGW) {
//        logfile = new char[strlen(PASER_LOG_FILE) + 1];
//        strcpy(logfile, PASER_LOG_FILE);
//    } else {
//        if (configFile[0] == 'r') {
//            logfile = new char[strlen("log_router.log") + 1];
//            strcpy(logfile, "log_router.log");
//        } else {
//            logfile = new char[strlen("log_router2.log") + 1];
//            strcpy(logfile, "log_router2.log");
//        }
//    }
//
//    netDeviceNumber = 1;
//    netDevice = NULL;
//    if (netDeviceNumber > 0) {
//        netDevice = new network_device[netDeviceNumber];
//        netDevice[0].enabled = 1;
//        netDevice[0].sock = -1;
//        netDevice[0].icmp_sock = -1;
//        netDevice[0].bcast.s_addr = PASER_BROADCAST;
//        if (isGW) {
//            inet_aton("10.20.30.40", &netDevice[0].ipaddr);
//        } else {
//            if (configFile[0] == 'r') {
//                inet_aton("10.20.30.41", &netDevice[0].ipaddr);
//            } else {
//                inet_aton("10.20.30.42", &netDevice[0].ipaddr);
//            }
//        }
//        netDevice[0].ifindex = 10;
//        strcpy(netDevice[0].ifname, "wlan");
//    }
//
//    if (isGW) {
//        netEthDeviceNumber = 1;
//    } else {
//        netEthDeviceNumber = 0;
//    }
//
//    netEthDevice = NULL;
//    if (netEthDeviceNumber > 0) {
//        netEthDevice = new network_device[netEthDeviceNumber];
//        netEthDevice[0].enabled = 1;
//        netEthDevice[0].sock = -1;
//        netEthDevice[0].icmp_sock = -1;
//        netEthDevice[0].bcast.s_addr = PASER_BROADCAST;
//        inet_aton("11.21.31.41", &netEthDevice[0].ipaddr);
//        netEthDevice[0].ifindex = 22;
//        strcpy(netEthDevice[0].ifname, "eth0");
//    }
//
//    netAddDevice = NULL;
//    netAddDeviceNumber = 0;
//    if (configFile[0] != '2') {
//        intAddlList();
//    }
//
//    inet_aton("15.25.35.45", &addressOfKDC);
//#else
//#ifdef PASER_SOCKET_TEST
//    isGW = true;
//
//    logfile = new char[strlen(PASER_LOG_FILE) + 1];
//    strcpy(logfile, PASER_LOG_FILE);
//
//    netDeviceNumber = 1;
//    netDevice = NULL;
//    if (netDeviceNumber > 0) {
//        netDevice = new network_device[netDeviceNumber];
//        netDevice[0].enabled = 1;
//        netDevice[0].sock = -1;
//        netDevice[0].icmp_sock = -1;
//        netDevice[0].bcast.s_addr = PASER_BROADCAST;
//        inet_aton("192.168.56.1", &netDevice[0].ipaddr);
//        netDevice[0].ifindex = 1;
//        strcpy(netDevice[0].ifname, "vboxnet0");
//    }
//
//    if (isGW) {
//        netEthDeviceNumber = 1;
//    } else {
//        netEthDeviceNumber = 0;
//    }
//    netEthDevice = NULL;
//    if (netEthDeviceNumber > 0) {
//        netEthDevice = new network_device[netEthDeviceNumber];
//        netEthDevice[0].enabled = 1;
//        netEthDevice[0].sock = -1;
//        netEthDevice[0].icmp_sock = -1;
//        netEthDevice[0].bcast.s_addr = PASER_BROADCAST;
//        inet_aton("172.17.1.98", &netEthDevice[0].ipaddr);
//        netEthDevice[0].ifindex = 22;
//        strcpy(netEthDevice[0].ifname, "eth0");
//    }
//
//    netAddDevice = NULL;
//    netAddDeviceNumber = 0;
//
//    inet_aton("127.0.0.1", &addressOfKDC);
//#else
//
//#endif //#ifdef PASER_SOCKET_TEST
//#endif //#ifdef PASER_MODULE_TEST
//    // load path to certificates
//    if (isGW) {
//        certfile = new char[strlen(PASER_gw_cert_file) + 1];
//        strcpy(certfile, PASER_gw_cert_file);
//        keyfile = new char[strlen(PASER_gw_cert_key_file) + 1];
//        strcpy(keyfile, PASER_gw_cert_key_file);
//    } else {
//        certfile = new char[strlen(PASER_cert_file) + 1];
//        strcpy(certfile, PASER_cert_file);
//        keyfile = new char[strlen(PASER_cert_key_file) + 1];
//        strcpy(keyfile, PASER_cert_key_file);
//    }
//    cafile = new char[strlen(PASER_CA_cert_file) + 1];
//    strcpy(cafile, PASER_CA_cert_file);
//
//    maxHopCountForLocalRepair = 10;
//
//    root_repetitions_timeout = 1000;
//    root_repetitions = 3;
//
//    setGWsearch = false;
//
//    LinkLayerFeeback = true;
//
//    LocalRepair = true;
//
//}

PASER_config::PASER_config(struct paserd_conf *configData) {
    unsigned int i;
    resetHelloByBroadcast = false;
    LOG_LVL = configData->LOG_LVL;
    LOG_CONFIGURATION = configData->LOG_CONFIGURATION;
    LOG_SCHEDULER = configData->LOG_SCHEDULER;
    LOG_INIT_MODULES = configData->LOG_INIT_MODULES;
    LOG_INVALID_PACKET = configData->LOG_INVALID_PACKET;
    LOG_ROUTE_DISCOVERY = configData->LOG_ROUTE_DISCOVERY;
    LOG_PACKET_PROCESSING = configData->LOG_PACKET_PROCESSING;
    LOG_ROUTING_TABLE = configData->LOG_ROUTING_TABLE;
    LOG_PACKET_INFO = configData->LOG_PACKET_INFO;
    LOG_TIMEOUT_INFO = configData->LOG_TIMEOUT_INFO;
    LOG_CRYPTO_ERROR = configData->LOG_CRYPTO_ERROR;
    LOG_ERROR = configData->LOG_ERROR;
    LOG_CONNECTION = configData->LOG_CONNECTION;

    isGW = configData->IsGateway;

    logfile = new char[configData->logFile.length() + 1];
    strcpy(logfile, configData->logFile.c_str());

    netDeviceNumber = configData->interface.size();
    netDevice = NULL;
    if (netDeviceNumber > 0) {
        netDevice = new network_device[netDeviceNumber];
    }

    for (i = 0; i < netDeviceNumber; i++) {
        netDevice[i].enabled = 1;
        netDevice[i].sock = -1;
        netDevice[i].icmp_sock = -1;
        netDevice[i].bcast.s_addr = PASER_BROADCAST;
        inet_aton(configData->interface.at(i).IPv4_addr.c_str(), &netDevice[i].ipaddr);
        netDevice[i].ifindex = 1 + i;
        strcpy(netDevice[i].ifname, configData->interface.at(i).name.c_str());
    }

    netEthDevice = NULL;
    if (configData->IsGateway) {
        netEthDeviceNumber = 1;
        if (netEthDeviceNumber > 0) {
            netEthDevice = new network_device[netEthDeviceNumber];
            netEthDevice[0].enabled = 1;
            netEthDevice[0].sock = -1;
            netEthDevice[0].icmp_sock = -1;
            netEthDevice[0].bcast.s_addr = PASER_BROADCAST;
            inet_aton("127.0.0.1", &netEthDevice[0].ipaddr);
            netEthDevice[0].ifindex = 22;
            strcpy(netEthDevice[0].ifname, "lo");
        }
    } else {
        netEthDeviceNumber = 0;
    }

    netAddDevice = NULL;
    netAddDeviceNumber = configData->interfaceSubnetwork.size();

    if (netAddDeviceNumber > 0) {
        netAddDevice = new network_device[netAddDeviceNumber];

        for (u_int32_t i = 0; i < netAddDeviceNumber; i++) {
            netAddDevice[i].enabled = 1;
            netAddDevice[i].sock = -1;
            netAddDevice[i].icmp_sock = -1;
            inet_aton(configData->interfaceSubnetwork.at(i).IPv4_mask.c_str(), &netAddDevice[i].mask);
            inet_aton(configData->interfaceSubnetwork.at(i).IPv4_addr.c_str(), &netAddDevice[i].ipaddr);
            netAddDevice[i].ifindex = i + netDeviceNumber + 1;
            strcpy(netAddDevice[i].ifname, configData->interfaceSubnetwork.at(i).name.c_str());
        }

        for (u_int32_t i = 0; i < netAddDeviceNumber; i++) {
            address_range tempRange;
            tempRange.ipaddr = netAddDevice[i].ipaddr;
            tempRange.mask = netAddDevice[i].mask;
            AddL.push_back(tempRange);
        }
    }

    inet_aton(configData->KDCIPAddress.c_str(), &addressOfKDC);

    // load path to certificates
    if (isGW) {
        certfile = new char[strlen(PASER_gw_cert_file) + 1];
        strcpy(certfile, PASER_gw_cert_file);
        keyfile = new char[strlen(PASER_gw_cert_key_file) + 1];
        strcpy(keyfile, PASER_gw_cert_key_file);
    } else {
        certfile = new char[strlen(PASER_cert_file) + 1];
        strcpy(certfile, PASER_cert_file);
        keyfile = new char[strlen(PASER_cert_key_file) + 1];
        strcpy(keyfile, PASER_cert_key_file);
    }
    cafile = new char[strlen(PASER_CA_cert_file) + 1];
    strcpy(cafile, PASER_CA_cert_file);

    maxHopCountForLocalRepair = 10;

    root_repetitions_timeout = 1000;
    root_repetitions = 3;

    setGWsearch = false;

    LinkLayerFeeback = true;

    LocalRepair = true;

}

PASER_config::~PASER_config() {
    delete[] certfile;
    delete[] keyfile;
    delete[] cafile;
    delete[] logfile;

    if (netDevice) {
        delete[] netDevice;
    }
    if (netEthDevice) {
        delete[] netEthDevice;
    }
    if (netAddDevice) {
        delete[] netAddDevice;
    }

}

bool PASER_config::getIsGW() {
    return isGW;
}

char *PASER_config::getCertfile() {
    return certfile;
}

char *PASER_config::getKeyfile() {
    return keyfile;
}

char *PASER_config::getCAfile() {
    return cafile;
}

char *PASER_config::getLog() {
    return logfile;
}

bool PASER_config::isGWsearch() {
    return setGWsearch;
}

u_int32_t PASER_config::getNetDeviceNumber() {
    return netDeviceNumber;
}

int PASER_config::getLOG_LVL(){
    return LOG_LVL;
}
int PASER_config::getLOG_CONFIGURATION(){
    return LOG_CONFIGURATION;
}
int PASER_config::getLOG_SCHEDULER(){
    return LOG_SCHEDULER;
}
int PASER_config::getLOG_INIT_MODULES(){
    return LOG_INIT_MODULES;
}
int PASER_config::getLOG_INVALID_PACKET(){
    return LOG_INVALID_PACKET;
}
int PASER_config::getLOG_ROUTE_DISCOVERY(){
    return LOG_ROUTE_DISCOVERY;
}
int PASER_config::getLOG_PACKET_PROCESSING(){
    return LOG_PACKET_PROCESSING;
}
int PASER_config::getLOG_ROUTING_TABLE(){
    return LOG_ROUTING_TABLE;
}
int PASER_config::getLOG_PACKET_INFO(){
    return LOG_PACKET_INFO;
}
int PASER_config::getLOG_TIMEOUT_INFO(){
    return LOG_TIMEOUT_INFO;
}
int PASER_config::getLOG_CRYPTO_ERROR(){
    return LOG_CRYPTO_ERROR;
}
int PASER_config::getLOG_ERROR(){
    return LOG_ERROR;
}
int PASER_config::getLOG_CONNECTION(){
    return LOG_CONNECTION;
}

network_device *PASER_config::getNetDevice() {
    return netDevice;
}

u_int32_t PASER_config::getNetEthDeviceNumber() {
    return netEthDeviceNumber;
}

network_device *PASER_config::getNetEthDevice() {
    return netEthDevice;
}

u_int32_t PASER_config::getNetAddDeviceNumber() {
    return netAddDeviceNumber;
}

network_device *PASER_config::getNetAddDevice() {
    return netAddDevice;
}

bool PASER_config::isResetHelloByBroadcast() {
    return resetHelloByBroadcast;
}

bool PASER_config::isLinkLayerFeeback() {
    return LinkLayerFeeback;
}

bool PASER_config::isLocalRepair() {
    return LocalRepair;
}

int PASER_config::getMaxLocalRepairHopCount() {
    return maxHopCountForLocalRepair;
}

u_int32_t PASER_config::getRootRepetitionsTimeout() {
    return root_repetitions_timeout;
}

u_int32_t PASER_config::getRootRepetitions() {
    return root_repetitions;
}

/**
 * Initialize the Array of node's subnetworks
 */
void PASER_config::intAddlList() {
#ifdef PASER_MODULE_TEST
    int wlanNumber = 2;
    netAddDeviceNumber = wlanNumber - netDeviceNumber;
    if (netAddDeviceNumber <= 0) {
        return;
    }
    netAddDevice = new network_device[netAddDeviceNumber];

    for (u_int32_t i = 0; i < netAddDeviceNumber; i++) {
        netAddDevice[i].enabled = 1;
        netAddDevice[i].sock = -1;
        netAddDevice[i].icmp_sock = -1;
        inet_aton("255.255.255.0", &netAddDevice[i].mask);
        if (isGW) {
            inet_aton("10.20.60.1", &netAddDevice[i].ipaddr);
        } else {
            inet_aton("10.20.60.2", &netAddDevice[i].ipaddr);
        }
        netAddDevice[i].ifindex = i + netDeviceNumber + 1;
        strcpy(netAddDevice[i].ifname, "sub");
    }

    for (u_int32_t i = 0; i < netAddDeviceNumber; i++) {
        address_range tempRange;
        tempRange.ipaddr = netAddDevice[i].ipaddr;
        tempRange.mask = netAddDevice[i].mask;
        AddL.push_back(tempRange);

//        struct in_addr emptyAddr;
//        emptyAddr.s_addr = (in_addr_t) 0x00000000;
//        routing_table->updateKernelRoutingTable(tempRange.ipaddr, emptyAddr, tempRange.mask, 1, false, netAddDevice[i].ifindex);
    }
#else   //#ifdef PASER_MODULE_TEST
#ifdef PASER_SOCKET_TEST
#else   //#ifdef PASER_SOCKET_TEST
#endif  //#ifdef PASER_SOCKET_TEST
#endif  //#ifdef PASER_MODULE_TEST
}

std::list<address_range> PASER_config::getAddL() {
    return AddL;
}

/**
 * Test if the entered address <b>Addr</b> in the own subnetworks is
 *
 *@param Addr IP address that will be checked
 */
bool PASER_config::isAddInMySubnetwork(struct in_addr Addr) {
    for (u_int32_t i = 0; i < netAddDeviceNumber; i++) {
        if ((netAddDevice[i].mask.s_addr & Addr.s_addr) == (netAddDevice[i].mask.s_addr & netAddDevice[i].ipaddr.s_addr)) {
            return true;
        }
    }
    return false;
}

/**
 * Check if the entered address <b>Addr</b> the own IP address is
 *
 *@param Addr IP address that will be checked
 */
bool PASER_config::isAddInMyLocalAddress(struct in_addr Addr) {
    for (u_int32_t i = 0; i < netDeviceNumber; i++) {
        if (netDevice[i].ipaddr.s_addr == Addr.s_addr) {
            return true;
        }
    }
    return false;
}

struct in_addr PASER_config::getAddressOfKDC() {
    return addressOfKDC;
}

int PASER_config::getIfIdFromIfIndex(uint32_t ifIndex) {
    for (u_int32_t i = 0; i < netDeviceNumber; i++) {
        if (netDevice[i].enabled == 1 && netDevice[i].ifindex == ifIndex) {
            return i;
        }
    }
    return -1;
}

int PASER_config::getIfIdFromAddress(in_addr ip) {
    for (u_int32_t i = 0; i < netDeviceNumber; i++) {
        if (netDevice[i].enabled == 1 && netDevice[i].ipaddr.s_addr == ip.s_addr) {
            return i;
        }
    }
    return -1;
}
