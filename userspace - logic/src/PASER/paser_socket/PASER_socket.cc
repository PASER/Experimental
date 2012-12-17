/**
 *\class  		PASER_socket
 *@brief       	Class provides an interface to kernel space and to network device/wireless card.
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

#include "PASER_socket.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
//#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netlink/netlink.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/route.h>
#include <netlink/cli/link.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>


//#include "rom.h"
#include "rom_client.h"

#define SO_RECVBUF_SIZE (10 * 1024)

PASER_socket::PASER_socket(PASER_global *paser_global) {
    pGlobal = paser_global;

    lastPacket.len = 0;
    lastPacket.buf = NULL;

    socketToKernel = -1;
    ctx = NULL;
#ifndef PASER_MODULE_TEST
    // initialize PASER sockets
    initDeviceSockets();

    // initialize kernel Socket
    initSocketToKernel();

    // initialize rom_policy ROM_A_UNSPEC
    rom_genl_policy[ROM_A_UNSPEC].type = NLA_U32;
    rom_genl_policy[ROM_A_UNSPEC].minlen = 0;
    rom_genl_policy[ROM_A_UNSPEC].maxlen = 0xFFFF;
    rom_genl_policy[ROM_A_DST].type = NLA_U32;
    rom_genl_policy[ROM_A_DST].minlen = 0;
    rom_genl_policy[ROM_A_DST].maxlen = 0xFFFF;
    rom_genl_policy[ROM_A_MASK].type = NLA_U32;
    rom_genl_policy[ROM_A_MASK].minlen = 0;
    rom_genl_policy[ROM_A_MASK].maxlen = 0xFFFF;
    rom_genl_policy[ROM_A_ROUTE].type = NLA_U32;
    rom_genl_policy[ROM_A_ROUTE].minlen = 0;
    rom_genl_policy[ROM_A_ROUTE].maxlen = 0xFFFF;
    rom_genl_policy[ROM_A_ERR_HOST].type = NLA_U32;
    rom_genl_policy[ROM_A_ERR_HOST].minlen = 0;
    rom_genl_policy[ROM_A_ERR_HOST].maxlen = 0xFFFF;
    rom_genl_policy[ROM_A_GWSTATE].type = NLA_U8;
    rom_genl_policy[ROM_A_GWSTATE].minlen = 0;
    rom_genl_policy[ROM_A_GWSTATE].maxlen = 0xFFFF;

    rom = new rom_client(pGlobal);
    // initialize SSL structure
    const SSL_METHOD *meth;

    meth = SSLv3_client_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Error! SSL_CTX_new (meth)\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        exit(1);
    }
    // load own certificate
    if (SSL_CTX_use_certificate_file(ctx, pGlobal->getPaser_configuration()->getCertfile(), SSL_FILETYPE_PEM) <= 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't load certificate\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        exit(1);
    }
    // load private key of own certificate
    if (SSL_CTX_use_PrivateKey_file(ctx, pGlobal->getPaser_configuration()->getKeyfile(), SSL_FILETYPE_PEM) <= 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't load private key\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        exit(1);
    }
    // load CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, PASER_CA_cert_file, NULL)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't load CA file\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        exit(1);
    }

    STACK_OF(X509_NAME) *cert_names;
    // load CA certificate which will be sent for client authentication
    cert_names = SSL_load_client_CA_file(PASER_CA_cert_file);
    if (cert_names != NULL)
        SSL_CTX_set_client_CA_list(ctx, cert_names);
    else {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_load_client_CA_file failed\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        exit(1);
    }
    // check own private key
    if (!SSL_CTX_check_private_key(ctx)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Private key does not match the certificate public key\n");
        exit(1);
    }
    // set verify option. SSL_VERIFY_PEER - the certificate of the peer will be verified
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // Set the verification depth to 1
    SSL_CTX_set_verify_depth(ctx, 1);
#endif
}

PASER_socket::~PASER_socket() {
    if (lastPacket.len > 0) {
        free(lastPacket.buf);
    }
    lastPacket.len = 0;
    lastPacket.buf = NULL;

#ifndef PASER_MODULE_TEST
    delete rom;

    // close sockets
    for (uint32_t i = 0; i < pGlobal->getPaser_configuration()->getNetDeviceNumber(); i++) {
        if (!DEV_NR(i).enabled)
        continue;
        close(DEV_NR(i).sock);
    }
    for (std::map<int, SSL*>::iterator it = socketMap.begin(); it != socketMap.end(); it++) {
        if (!SSL_get_shutdown(it->second))
            SSL_shutdown(it->second);
        close(it->first);
        SSL_free(it->second);
    }

    nl_socket_free(sk);
#endif
    if (ctx) {
        SSL_CTX_free(ctx);
    }

}

void PASER_socket::initDeviceSockets() {
    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "Initialize Sockets\n");
    struct sockaddr_in paser_addr;
    char ifname[IFNAMSIZ];
    unsigned int i;
    int on = 1;
    int tos = IPTOS_LOWDELAY;
    int bufsize = SO_RECVBUF_SIZE;
    socklen_t bufoptlen = sizeof(bufsize);

    PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "getNetDeviceNumber: %d\n", pGlobal->getPaser_configuration()->getNetDeviceNumber());

    // Check if there are no interfaces
    if (pGlobal->getPaser_configuration()->getNetDeviceNumber() == 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "No interfaces configured\nError: (%d)%s\n", errno, strerror(errno));
        exit(1);
    }

    // For each interface...
    for (i = 0; i < pGlobal->getPaser_configuration()->getNetDeviceNumber(); i++) {
        // open a socket just on enabled interface
        if (!DEV_NR(i).enabled)
        continue;

        PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "Initialize Socket on %s, IP: %s\n", DEV_NR(i).ifname, inet_ntoa(DEV_NR(i).ipaddr));

        // Create an UDP socket
        if ((DEV_NR(i).sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "socket() failed on interface %d\nError: (%d)%s", i, errno, strerror(errno));
            exit(1);
        }

        // Enable the datagram socket as a broadcast one
        if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "setsockopt(SO_REUSEADDR) failed on interface %d\nError: (%d)%s\n",
                    i, errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Enable the datagram socket as a broadcast one
        if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "setsockopt(BROADCAST) failed on interface %d\nError: (%d)%s\n",
                    i, errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Make the socket only process packets received from an interface
        strncpy(ifname, DEV_NR(i).ifname, sizeof(ifname));

        if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_BINDTODEVICE, &ifname, sizeof(ifname)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "setsockopt(BINDTODEVICE) failed for %s\nError: (%d)%s\n",
                    DEV_NR(i).ifname, errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Bind to DYMO port number
        memset(&paser_addr, 0, sizeof(struct sockaddr_in));
        paser_addr.sin_family = AF_INET;
        paser_addr.sin_port = htons(PASER_PORT);
        paser_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(DEV_NR(i).sock, (struct sockaddr *) &paser_addr, sizeof(struct sockaddr)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "bind() failed on interface %d\nError: (%d)%s\n", i, errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Set priority of IP datagrams
        if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_PRIORITY, &tos, sizeof(int)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "setsockopt(PRIORITY) failed for LOWDELAY\nError: (%d)%s\n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Set receive buffer size ...\n");
        // Set maximum allowable receive buffer size
        for (;; bufsize -= 1024) {
            if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, bufoptlen) == 0) {
                PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "receive buffer size set to %d\n", bufsize);
                break;
            }
            if (bufsize < (1024 * 5)) {
                PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "could not set receive buffer size\n");
                exit(EXIT_FAILURE);
            }
        }
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "receive buffer size set to %d\n", bufsize);
    }

}

int PASER_socket::msg_handler(struct nlmsghdr *msg, void *arg) {
    __u32 dst_addr = 0;
    struct nlmsghdr *nlh = msg;
    struct nlattr *attrs[ROM_A_MAX + 1];
    in_addr dest;

    genlmsg_parse(nlh, 0, attrs, ROM_A_MAX, rom_genl_policy);

    if (attrs[ROM_A_DST]) {
        dst_addr = nla_get_u32(attrs[ROM_A_DST]);
        dest.s_addr = dst_addr;
        PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "[RREQ] Route for %d.%d.%d.%d requested(%s)\n", NIPQUAD(dst_addr), inet_ntoa(dest));
        pGlobal->getRoute_findung()->processPacket(DEV_NR(0).ipaddr, dest);
//        pGlobal->getRoute_findung()->route_discovery(dest, 0);
            } else if (attrs[ROM_A_ROUTE]) {
                dst_addr = nla_get_u32(attrs[ROM_A_ROUTE]);
                dest.s_addr = dst_addr;
                PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "[RLIFE] Update Link to %d.%d.%d.%d\n", NIPQUAD(dst_addr));
                pGlobal->getRouting_table()->updateRouteLifetimes(dest);
            } else if (attrs[ROM_A_ERR_HOST]) {
                dst_addr = nla_get_u32(attrs[ROM_A_ERR_HOST]);
                dest.s_addr = dst_addr;
                PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "[RERR] Link to %d.%d.%d.%d failed\n", NIPQUAD(dst_addr));
//        pGlobal->getRoute_maintenance()->packetFailed(dest, dest, true);
                PASER_routing_entry *rEntry = pGlobal->getRouting_table()->findDest(dest);
                if (rEntry) {
                    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Find invalid route entry\n");
                }
                if (rEntry && pGlobal->getPaser_configuration()->isLocalRepair()
                        && pGlobal->getPaser_configuration()->getMaxLocalRepairHopCount() >= rEntry->hopcnt) {
                    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Start route repair\n");
                    pGlobal->getRoute_maintenance()->packetFailed(dest, dest, false);
                    pGlobal->getRoute_findung()->processPacket(dest, dest);
                } else {
                    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTE_DISCOVERY, "Find invalid route entry\n");
                    pGlobal->getRoute_maintenance()->packetFailed(dest, dest, true);

                    struct timeval now;
                    pGlobal->getPASERtimeofday(&now);
                    pGlobal->getBlacklist()->setRerrTime(dest, now);
                }
                // add to statistic
                in_addr tempAddr;
                tempAddr.s_addr = dst_addr;
                pGlobal->getPaserStatistic()->routingTableModificationBreak(tempAddr);
            }

    return 0;
}

void PASER_socket::initSocketToKernel() {
	extern bool isRunning;
	int grp;

    sk = nl_socket_alloc();
    if (sk == NULL) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't initialize kernel socket.\n");
        exit(1);
    }
    nl_socket_disable_seq_check(sk);

//    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, msg_handler, NULL);

    nl_connect(sk, NETLINK_GENERIC);

    grp = genl_ctrl_resolve_grp(sk, "ROUTE-O-MATIC", "rom-mc-grp");
    while ((grp < 0) && isRunning) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "waiting to connect to \"rom-mc-grp\"\n");
        sleep(5);
        grp = genl_ctrl_resolve_grp(sk, "ROUTE-O-MATIC", "rom-mc-grp");
    }
//    grp = genl_ctrl_resolve_grp(sk, "ROUTE-O-MATIC", "rom-mc-grp");
//    if (grp < 0) {
//        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "genl_ctrl_resolve_grp() failed.\n");
//        exit(-1);
//    }

    nl_socket_add_memberships(sk, grp);

    socketToKernel = nl_socket_get_fd(sk);

}

lv_block PASER_socket::readDataFromKernel() {
    lv_block buffer;
    buffer.len = 0;
    buffer.buf = NULL;
    buffer.buf = (uint8_t*) malloc(SO_RECVBUF_SIZE + 1);
    int len;
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // Receive message
    if ((len = recvfrom(socketToKernel, buffer.buf, SO_RECVBUF_SIZE, 0, (struct sockaddr *) &sender_addr, &addr_len)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "could not receive message: %s(%d)", crt_strerror(errno), errno);
        free(buffer.buf);
        buffer.len = 0;
        buffer.buf = NULL;
        return buffer;
    }
    buffer.len = len;
    msg_handler((nlmsghdr *) buffer.buf, NULL);
    return buffer;
}

int PASER_socket::initEthSocket(network_device *netDevice) {
    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "Initialize Ethernet Socket (Connect to KDC)\n");
    if (!pGlobal->getPaser_configuration()->getIsGW() || !netDevice->enabled) {
        PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "Cann't initialize Ethernet socket(Not Gateway or netDevice->enabled = 0).\n");
        return -1;
    }
    int err;
    int tempSocket;
    struct sockaddr_in sa;
    X509* server_cert;
    char* str;
    SSL *ssl;

    /* Create a socket and connect to server using normal socket calls. */

    tempSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (tempSocket < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "socket() failed on interface %d. Error: (%d)%s\n", 0, errno, strerror(errno));
        return -1;
    }

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = pGlobal->getPaser_configuration()->getAddressOfKDC().s_addr; /* KDC IP */
    sa.sin_port = htons(PASER_PORT_KDC); /* KDC Port number */

    err = connect(tempSocket, (struct sockaddr*) &sa, sizeof(sa));
    if (err < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "connect() failed to IP: %s, Port: %d. Error: (%d)%s\n",
                inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), errno, strerror(errno));
        tempSocket = -1;
        return -1;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "Connect to KDC, IP: %s, Port: %d...OK.\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

    /* Now we have TCP conncetion. Start SSL negotiation. */

    ssl = SSL_new(ctx);
    if (!ssl) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_new(ctx) failed.\n");
        close(tempSocket);
        tempSocket = -1;
        return -1;
    }
    SSL_set_fd(ssl, tempSocket);
    err = SSL_connect(ssl);
    if (err == -1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_connect(ssl) failed.\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        SSL_free(ssl);
        ssl = NULL;
        close(tempSocket);
        tempSocket = -1;
        return -1;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "SSL handshake to KDC...OK.\n");

    /* Get the cipher - opt */
    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "SSL connection using %s\n", SSL_get_cipher (ssl));

    /* Get server's certificate (note: beware of dynamic allocation) - opt */

    server_cert = SSL_get_peer_certificate(ssl);
    if (!server_cert) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "KDC does not have certificate.\n");
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        tempSocket = -1;
        SSL_free(ssl);
        ssl = NULL;
        return -1;
    }

    err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_get_verify_result() failed: %s(%d)\n", crt_strerror(err), err);
        X509_free(server_cert);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        tempSocket = -1;
        SSL_free(ssl);
        ssl = NULL;
        return -1;
    }

    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "Server certificate:\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    if (!str) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't read subject name from KDC certificate.\n");
        X509_free(server_cert);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        tempSocket = -1;
        SSL_free(ssl);
        ssl = NULL;
        return -1;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    if (!str) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't read issuer name from KDC certificate.\n");
        X509_free(server_cert);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        tempSocket = -1;
        SSL_free(ssl);
        ssl = NULL;
        return -1;
    }
    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "\t issuer: %s\n", str);
    OPENSSL_free(str);

    /* Check certificate */
    if (!pGlobal->getCrypto_sign()->checkOneCert(server_cert)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Certificate is invalid.\n");
        X509_free(server_cert);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        tempSocket = -1;
        SSL_free(ssl);
        ssl = NULL;
        return -1;
    }
    if (!pGlobal->getCrypto_sign()->isKdcCert(server_cert)) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Certificate is not a KDC certificate.\n");
        X509_free(server_cert);
        if (!SSL_get_shutdown(ssl))
            SSL_shutdown(ssl);
        close(tempSocket);
        tempSocket = -1;
        SSL_free(ssl);
        ssl = NULL;
        return -1;
    }
    X509_free(server_cert);

    PASER_LOG_WRITE_LOG(PASER_LOG_CONFIGURATION, "Initialize Ethernet Socket...OK\n");

    socketMap.insert(std::make_pair(tempSocket, ssl));
    return tempSocket;
}

int PASER_socket::getSocketToKernel() {
    return socketToKernel;
}

void PASER_socket::sendUDPToIPOverNetwork(uint8_t *s, int length, const in_addr destAddr, int destPort, network_device *netDevice) {
    if (lastPacket.len > 0) {
        free(lastPacket.buf);
    }
#ifndef PASER_MODULE_TEST
    struct sockaddr_in dest_sockaddr;
    u_int8_t ttl;

    dest_sockaddr.sin_family = AF_INET;
    dest_sockaddr.sin_addr = destAddr;
    dest_sockaddr.sin_port = htons(destPort);

    // Set TTL
    ttl = PASER_IPTTL;
    if (setsockopt(netDevice->sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "setsockopt(IP_TTL) failed: %s(%d)\n", crt_strerror(errno), errno);
        exit(1);
    }
    // Send
    if (sendto(netDevice->sock, s, length, 0, (struct sockaddr *) &dest_sockaddr, sizeof(dest_sockaddr)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "failed send to %s: %s(%d)\n", inet_ntoa(destAddr), crt_strerror(errno), errno);
        lastPacket.len = 0;
        lastPacket.buf = NULL;
        return;
    }

    // add data to statistic
    pGlobal->getPaserStatistic()->addToSendBytes((long) lastPacket.len);
    if (destAddr.s_addr == PASER_BROADCAST ) {
        pGlobal->getPaserStatistic()->incBroadcastPackets();
    } else {
        pGlobal->getPaserStatistic()->incUnicastPackets();
    }
#endif
    lastPacket.len = length;
    lastPacket.buf = s;
}

bool PASER_socket::addRouteDev(in_addr destIP, in_addr destMask, network_device *netDevice) {
    rom->send(CAT_ROUTE, CMD_ROUTE_ADD, destIP, destMask, CMD2_DEV, destIP, netDevice);
    rom->send(CAT_CORE, CMD_CORE_RT_ADD, destIP, destMask, CMD2_UNSPEC, destIP, netDevice);
    return true;
}

bool PASER_socket::addDefaultRoute(in_addr destIP, network_device *netDevice, int metric) {
    if (pGlobal->getPaser_configuration()->getIsGW()) {
        return true;
    }
    rom->addDefaultRoute(destIP, netDevice, metric);
    return true;
}

bool PASER_socket::deleteDefaultRoute() {
    if (pGlobal->getPaser_configuration()->getIsGW()) {
        return true;
    }
    rom->deleteDefaultRoute();
    return true;
}

bool PASER_socket::addRouteVia(in_addr destIP, in_addr destMask, in_addr neighborIP) {
    rom->send(CAT_ROUTE, CMD_ROUTE_ADD, destIP, destMask, CMD2_VIA, neighborIP, NULL);
    rom->send(CAT_CORE, CMD_CORE_RT_ADD, destIP, destMask, CMD2_UNSPEC, destIP, NULL);
    return true;
}

bool PASER_socket::deleteRoute(in_addr destIP, in_addr destMask) {
    rom->send(CAT_ROUTE, CMD_ROUTE_DELETE, destIP, destMask, CMD2_UNSPEC, destIP, NULL);
    rom->send(CAT_CORE, CMD_CORE_RT_DELETE, destIP, destMask, CMD2_UNSPEC, destIP, NULL);
    return true;
}

bool PASER_socket::releaseQueue(in_addr destIP, in_addr destMask) {
    rom->send(CAT_QUEUE, CMD_QUEUE_RELEASE, destIP, destMask, CMD2_UNSPEC, destIP, NULL);
    return true;
}

bool PASER_socket::setGWFlag(bool flag) {
    if (pGlobal->getPaser_configuration()->getIsGW()) {
        return true;
    }
    in_addr destIP;
    if (flag) {
        destIP.s_addr = 1;
    } else {
        destIP.s_addr = 0;
    }
    rom->send(CAT_CORE, CMD_CORE_SETGW, destIP, destIP, CMD2_UNSPEC, destIP, NULL);
    return true;
}

bool PASER_socket::deleteQueue(in_addr destIP, in_addr destMask) {
//    rom->send(CAT_QUEUE, CMD_QUEUE_RELEASE, destIP, destMask, CMD2_UNSPEC, destIP, NULL);
    return true;
}

bool PASER_socket::releaseQueue_for_AddList(std::list<address_list> AddList) {
    for (std::list<address_list>::iterator it = AddList.begin(); it != AddList.end(); it++) {
        address_list tempList = (address_list) *it;
        for (std::list<address_range>::iterator it = tempList.range.begin(); it != tempList.range.end(); it++) {
            address_range destRange = (address_range) *it;
            struct in_addr dest_addr = destRange.ipaddr;
            struct in_addr mask_addr = destRange.mask;
            rom->send(CAT_QUEUE, CMD_QUEUE_RELEASE, dest_addr, mask_addr, CMD2_UNSPEC, dest_addr, NULL);
        }
    }

    return true;
}

void PASER_socket::sendUDPToIPOverSSL(uint8_t *s, int length, const in_addr destAddr, int destPort, network_device *netDevice) {
    if (lastPacket.len > 0) {
        free(lastPacket.buf);
    }
#ifndef PASER_MODULE_TEST
    //initialize new SSL connection
    int socket = initEthSocket(netDevice);
    if (socket == -1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't open Socket. The packet will not be sent.\n");
        free(s);
        lastPacket.len = 0;
        lastPacket.buf = NULL;
        return;
    }
    //get new SSL connection
    std::map<int, SSL*>::iterator it = socketMap.find(socket);
    if (it == socketMap.end()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't find Socket in SocketMap. The packet will not be sent.\n");
        free(s);
        lastPacket.len = 0;
        lastPacket.buf = NULL;
        return;
    }
    //send data on SSL connection
    int err = SSL_write(it->second, s, length);
    if (err == -1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_write failed.\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
    }
#endif
    lastPacket.len = length;
    lastPacket.buf = s;
}

lv_block PASER_socket::readDataFromNetwork(network_device *netDevice) {
    lv_block buffer;
    buffer.len = 0;
    buffer.buf = NULL;
    buffer.buf = (uint8_t*) malloc(SO_RECVBUF_SIZE + 1);
    int len;
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // Receive message
    if ((len = recvfrom(netDevice->sock, buffer.buf, SO_RECVBUF_SIZE, 0, (struct sockaddr *) &sender_addr, &addr_len)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "could not receive message: %s(%d)", crt_strerror(errno), errno);
        free(buffer.buf);
        buffer.len = 0;
        buffer.buf = NULL;
        return buffer;
    }
    buffer.len = len;
    return buffer;
}

lv_block PASER_socket::readDataFromSSL(int sock) {
    int err;
    lv_block buffer;
    //get SSL connection
    std::map<int, SSL*>::iterator it = socketMap.find(sock);
    if (it == socketMap.end()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't find Socket in SocketMap. The packet cann't be read.\n");
        buffer.len = -1;
        buffer.buf = NULL;
        return buffer;
    }
    buffer.buf = (uint8_t*) malloc(5 * 1024);
    err = SSL_read(it->second, buffer.buf, 5 * 1024 - 1);
    if (err == -1) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "SSL_read failed.\n");
        ERR_print_errors_fp(PASER_LOG_GET_FD);
        buffer.len = -1;
        free(buffer.buf);
        buffer.buf = NULL;
        return buffer;
    }
    if (err == 0) {
        buffer.len = 0;
        free(buffer.buf);
        buffer.buf = NULL;
        return buffer;
    }
    buffer.len = err;
    buffer.buf[err] = '\0';
    return buffer;
}

void PASER_socket::closeSSLSocket(int sock) {
    std::map<int, SSL*>::iterator it = socketMap.find(sock);
    if (it == socketMap.end()) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Cann't find Socket in SocketMap. Cann't free SSL connection.\n");
        return;
    }
    if (!SSL_get_shutdown(it->second))
        SSL_shutdown(it->second);
    close(it->first);
    SSL_free(it->second);
    socketMap.erase(it);
}

char const* PASER_socket::crt_strerror(int err) {
    switch (err) {
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        return "UNABLE_TO_DECRYPT_CERT_SIGNATURE";

    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        return "UNABLE_TO_DECRYPT_CRL_SIGNATURE";

    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        return "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";

    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        return "CERT_SIGNATURE_FAILURE";

    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        return "CRL_SIGNATURE_FAILURE";

    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        return "ERROR_IN_CERT_NOT_BEFORE_FIELD";

    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        return "ERROR_IN_CERT_NOT_AFTER_FIELD";

    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
        return "ERROR_IN_CRL_LAST_UPDATE_FIELD";

    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
        return "ERROR_IN_CRL_NEXT_UPDATE_FIELD";

    case X509_V_ERR_CERT_NOT_YET_VALID:
        return "CERT_NOT_YET_VALID";

    case X509_V_ERR_CERT_HAS_EXPIRED:
        return "CERT_HAS_EXPIRED";

    case X509_V_ERR_OUT_OF_MEM:
        return "OUT_OF_MEM";

    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        return "UNABLE_TO_GET_ISSUER_CERT";

    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return "UNABLE_TO_GET_ISSUER_CERT_LOCALLY";

    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        return "UNABLE_TO_VERIFY_LEAF_SIGNATURE";

    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return "DEPTH_ZERO_SELF_SIGNED_CERT";

    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        return "SELF_SIGNED_CERT_IN_CHAIN";

    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
        return "CERT_CHAIN_TOO_LONG";

    case X509_V_ERR_CERT_REVOKED:
        return "CERT_REVOKED";

    case X509_V_ERR_INVALID_CA:
        return "INVALID_CA";

    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        return "PATH_LENGTH_EXCEEDED";

    case X509_V_ERR_INVALID_PURPOSE:
        return "INVALID_PURPOSE";

    case X509_V_ERR_CERT_UNTRUSTED:
        return "CERT_UNTRUSTED";

    case X509_V_ERR_CERT_REJECTED:
        return "CERT_REJECTED";

    case X509_V_ERR_UNABLE_TO_GET_CRL:
        return "UNABLE_TO_GET_CRL";

    case X509_V_ERR_CRL_NOT_YET_VALID:
        return "CRL_NOT_YET_VALID";

    case X509_V_ERR_CRL_HAS_EXPIRED:
        return "CRL_HAS_EXPIRED";
    }

    return "Unknown verify error";
}
