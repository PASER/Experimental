/**
 *\class  		PASER_GTKREQ
 *@brief       	Class implements GTK-request messages
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

#include "PASER_GTKREQ.h"

PASER_GTKREQ::PASER_GTKREQ(const PASER_GTKREQ &m) {
    operator=(m);
}

PASER_GTKREQ::PASER_GTKREQ() {
    type = GTKREQ;
}

PASER_GTKREQ::~PASER_GTKREQ() {
    if (cert.len > 0) {
        free(cert.buf);
    }
}

PASER_GTKREQ* PASER_GTKREQ::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x09) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of gateway
    in_addr tempSrcAddr;
    if ((length + sizeof(tempSrcAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddr.s_addr, pointer, sizeof(tempSrcAddr.s_addr));
    pointer += sizeof(tempSrcAddr.s_addr);
    length += sizeof(tempSrcAddr.s_addr);

    // read IP address of gateway
    in_addr tempGWAddr;
    if ((length + sizeof(tempGWAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong Gateway Addr." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempGWAddr.s_addr, pointer, sizeof(tempGWAddr.s_addr));
    pointer += sizeof(tempGWAddr.s_addr);
    length += sizeof(tempGWAddr.s_addr);

    // read IP address of next hop
    in_addr tempNextHopAddr;
    if ((length + sizeof(tempNextHopAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong next hop address." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempNextHopAddr.s_addr, pointer, sizeof(tempNextHopAddr.s_addr));
    pointer += sizeof(tempNextHopAddr.s_addr);
    length += sizeof(tempNextHopAddr.s_addr);

    // read Sending node's nonce
    u_int32_t tempNonce;
    if ((length + sizeof(tempNonce)) > l) {
        std::cout << "ERROR: Wrong nonce." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempNonce, pointer, sizeof(tempNonce));
    pointer += sizeof(tempNonce);
    length += sizeof(tempNonce);

    // read Length of Certificate
    u_int32_t tempCertL;
    if ((length + sizeof(tempCertL)) > l) {
        std::cout << "ERROR: Wrong length of certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempCertL, pointer, sizeof(tempCertL));
    pointer += sizeof(tempCertL);
    length += sizeof(tempCertL);

    // read Certificate
    u_int8_t * tempCert;
    if ((length + tempCertL) > l) {
        std::cout << "ERROR: Wrong certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREQ packet from given char array." << std::endl;
        return NULL;
    }
    tempCert = (uint8_t *) malloc(tempCertL);
    memcpy((uint8_t *) tempCert, pointer, tempCertL);
    pointer += tempCertL;
    length += tempCertL;

    PASER_GTKREQ *tempPacket = new PASER_GTKREQ();
    tempPacket->type = GTKREQ;
    tempPacket->srcAddress_var.s_addr = tempSrcAddr.s_addr;
    tempPacket->gwAddr.s_addr = tempGWAddr.s_addr;
    tempPacket->nextHopAddr.s_addr = tempNextHopAddr.s_addr;
    tempPacket->nonce = tempNonce;
    tempPacket->cert.len = tempCertL;
    tempPacket->cert.buf = tempCert;
    return tempPacket;
}

PASER_GTKREQ& PASER_GTKREQ::operator =(const PASER_GTKREQ &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
//    destAddress_var.s_addr = m.destAddress_var.s_addr;
//    seq = m.seq;

// PASER_GTKREQ
    gwAddr.s_addr = m.gwAddr.s_addr;
    nextHopAddr.s_addr = m.nextHopAddr.s_addr;

    cert.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.cert.len));
    memcpy(cert.buf, m.cert.buf, (sizeof(uint8_t) * m.cert.len));
    cert.len = m.cert.len;

    nonce = m.nonce;

    return *this;
}

std::string PASER_GTKREQ::detailedInfo() const {
    std::stringstream out;
    out << "Type: PASER_GTKREQ = " << (int) type << "\n";
    out << " IP of Source node: " << inet_ntoa(srcAddress_var) << "\n";
    out << " IP of gateway: " << inet_ntoa(gwAddr) << "\n";
    out << " IP of next hop: " << inet_ntoa(nextHopAddr) << "\n";
    out << " Nonce: " << nonce << "\n";
    out << " Cert length: " << cert.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " Cert buf: 0x";
        for (int32_t i = 0; i < cert.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) cert.buf[i] << std::dec;
        }
        out << "\n";
    }
    return out.str();
}

uint8_t * PASER_GTKREQ::toByteArray(int *l) {
    // Compute length of the packet
    int len = 0;
    len += 1; // Type of PASER packets
    len += sizeof(srcAddress_var.s_addr); // source's IP address
    len += sizeof(gwAddr.s_addr); // Gateway's IP address
    len += sizeof(nextHopAddr.s_addr); // nextHop's IP address
    len += sizeof(nonce); // Sending node's nonce

    len += sizeof(cert.len); // Length of Certificate
    len += cert.len; // Certificate

    // Allocate block of size "len" bytes memory.
    uint8_t *data = (uint8_t *) malloc(len);
    uint8_t *buf;
    buf = data;
    //messageType
    data[0] = 0x09;
    buf++;

    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
    buf += sizeof(srcAddress_var.s_addr); // Source's IP address
    memcpy(buf, (uint8_t *) &gwAddr.s_addr, sizeof(gwAddr.s_addr));
    buf += sizeof(gwAddr.s_addr); // Gateway's IP address
    memcpy(buf, (uint8_t *) &nextHopAddr.s_addr, sizeof(nextHopAddr.s_addr));
    buf += sizeof(nextHopAddr.s_addr); // nextHop's IP address
    memcpy(buf, (uint8_t *) &nonce, sizeof(nonce));
    buf += sizeof(nonce);     // nonce

    // Cert of querying node
    memcpy(buf, (uint8_t *) &cert.len, sizeof(cert.len));
    buf += sizeof(cert.len);
    memcpy(buf, cert.buf, cert.len);
    buf += cert.len;

    *l = len;
    return data;
}

uint8_t * PASER_GTKREQ::getCompleteByteArray(int *l) {
    int len = 0;
    uint8_t *packet = toByteArray(&len);
    *l = len;
    return packet;
}
