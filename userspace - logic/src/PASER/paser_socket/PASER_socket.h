/**
 *\class  		PASER_socket
 *@brief       	Class provides an interface to kernel space and to network device/wireless card.
 *@ingroup		Socket
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

class PASER_socket;

#ifndef PASER_socket_H_
#define PASER_socket_H_

#include "../config/PASER_defs.h"
#include "../config/PASER_global.h"
#include "rom_client.h"

#include <list>
#include <map>

#include <openssl/ssl.h>

#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/socket.h>
#include <netlink/msg.h>

#include <stdio.h>
#include <stdlib.h>

#include "rom.h"

/**
 * The main PASER class.
 */
class PASER_socket {
private:
    // PASER Sockets
    int socketToKernel;
    struct nl_sock *sk;
    rom_client *rom;
    struct nla_policy rom_genl_policy[ROM_A_MAX + 1];

    SSL_CTX* ctx;
    PASER_global* pGlobal;

    lv_block lastPacket;

    std::map<int, SSL*> socketMap;

public:
    PASER_socket(PASER_global *paser_global);
    ~PASER_socket();

    int getSocketToKernel();

    /**
     * Send PASER packet over PASER network.
     */
    void sendUDPToIPOverNetwork(uint8_t *s, int length, const in_addr destAddr, int destPort, network_device *netDevice);

    /**
     * Send PASER packet over SSL connection.
     */
    void sendUDPToIPOverSSL(uint8_t *s, int length, const in_addr destAddr, int destPort, network_device *netDevice);

    /**
     * Read a data from socket.
     *
     *@param b length of reading data. Will be set after function call.
     *@param netDevice Pointer to network device on which data is available.
     *
     *@return on success, Pointer to Buffer. On Error NULL.
     */
    lv_block readDataFromNetwork(network_device *netDevice);

    /**
     * Read a data from socket.
     *
     *@param sock File descriptor of socket on which data is available.
     *
     *@return on success, lv_block of Buffer.
     */
    lv_block readDataFromSSL(int sock);

    /**
     * Read a data from kernel
     * @return on success, lv_block of reading data.
     */
    lv_block readDataFromKernel();

    /**
     * Get last sent packet.
     * @return last sent packet.
     */
    lv_block getLastPacket() {
        return lastPacket;
    }

    /**
     * Close SSL Socket on given socket
     *
     * @param sock Socket FD
     */
    void closeSSLSocket(int sock);

    std::map<int, SSL*> getSocketMap() {
        return socketMap;
    }

    bool addRouteDev(in_addr destIP, in_addr destMask, network_device *netDevice);

    bool addDefaultRoute(in_addr destIP, network_device *netDevice, int metric);

    bool deleteDefaultRoute();

    bool addRouteVia(in_addr destIP, in_addr destMask, in_addr neighborIP);

    bool deleteRoute(in_addr destIP, in_addr destMask);

    bool releaseQueue(in_addr destIP, in_addr destMask);

    bool releaseQueue_for_AddList(std::list<address_list> AddList);

    bool deleteQueue(in_addr destIP, in_addr destMask);

    bool setGWFlag(bool flag);

private:
    /**
     * The function initialize all PASER sockets on which PASER protocol is active.
     */
    void initDeviceSockets();

    /**
     * Initialize a NetLink socket and connect it to kernel module.
     */
    void initSocketToKernel();

    /**
     * If the node is a gateway then the function will initialize Ethernet Socket and
     * connect it to KDC.
     */
    int initEthSocket(network_device *netDevice);

    char const* crt_strerror(int err);

    int msg_handler(struct nlmsghdr *msg, void *arg);
};

#endif /* PASER_socket_H_ */
