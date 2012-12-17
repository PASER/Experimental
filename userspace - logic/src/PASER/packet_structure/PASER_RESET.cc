/**
 *\class  		PASER_RESET
 *@brief       	Class implements PASER_RESET messages
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

#include "PASER_RESET.h"

#include <openssl/sha.h>
#include <openssl/x509.h>

/**
 * Constructor of PASER_RESET packet that creates an exact copy of another packets.
 *
 *@param m the pointer to the packet to copy
 */
PASER_RESET::PASER_RESET(const PASER_RESET &m) {
    operator=(m);
}

/**
 * Constructor of PASER_RESET packet that creates a new packet.
 *
 *@param src ip address of sending node
 */
PASER_RESET::PASER_RESET(struct in_addr src) {
    type = B_RESET;
    srcAddress_var = src;
    destAddress_var = src;
    seq = 0;

    sign.buf = NULL;
    sign.len = 0;

}

PASER_RESET::PASER_RESET() {
    type = B_RESET;
    seq = 0;

    sign.buf = NULL;
    sign.len = 0;
}

PASER_RESET* PASER_RESET::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x08) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of source node
    in_addr tempSrcAddr;
    if ((length + sizeof(tempSrcAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddr.s_addr, pointer, sizeof(tempSrcAddr.s_addr));
    pointer += sizeof(tempSrcAddr.s_addr);
    length += sizeof(tempSrcAddr.s_addr);

    // read GTK number
    u_int32_t tempKeyNr;
    if ((length + sizeof(tempKeyNr)) > l) {
        std::cout << "ERROR: Wrong KeyNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempKeyNr, pointer, sizeof(tempKeyNr));
    pointer += sizeof(tempKeyNr);
    length += sizeof(tempKeyNr);

    // read Length of Certificate
    u_int32_t tempCertL;
    if ((length + sizeof(tempCertL)) > l) {
        std::cout << "ERROR: Wrong length of certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempCertL, pointer, sizeof(tempCertL));
    pointer += sizeof(tempCertL);
    length += sizeof(tempCertL);

    // read Certificate
    u_int8_t * tempCert;
    if ((length + tempCertL) > l) {
        std::cout << "ERROR: Wrong certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        return NULL;
    }
    tempCert = (uint8_t *) malloc(tempCertL);
    memcpy((uint8_t *) tempCert, pointer, tempCertL);
    pointer += tempCertL;
    length += tempCertL;

    // read Length of Signature
    u_int32_t tempSignL;
    if ((length + sizeof(tempSignL)) > l) {
        std::cout << "ERROR: Wrong length of signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        free(tempCert);
        return NULL;
    }
    memcpy((uint8_t *) &tempSignL, pointer, sizeof(tempSignL));
    pointer += sizeof(tempSignL);
    length += sizeof(tempSignL);

    // read Signature
    u_int8_t * tempSign;
    if ((length + tempSignL) > l) {
        std::cout << "ERROR: Wrong signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_RESET packet from given char array." << std::endl;
        free(tempCert);
        return NULL;
    }
    tempSign = (uint8_t *) malloc(tempSignL);
    memcpy((uint8_t *) tempSign, pointer, tempSignL);
    pointer += tempSignL;
    length += tempSignL;

    PASER_RESET *tempPacket = new PASER_RESET();
    tempPacket->type = B_RESET;
    tempPacket->srcAddress_var.s_addr = tempSrcAddr.s_addr;
    tempPacket->keyNr = tempKeyNr;
    tempPacket->cert.len = tempCertL;
    tempPacket->cert.buf = tempCert;
    tempPacket->sign.len = tempSignL;
    tempPacket->sign.buf = tempSign;
    return tempPacket;
}
/**
 * Destructor
 */
PASER_RESET::~PASER_RESET() {
    free(cert.buf);
    free(sign.buf);
}

/**
 * Function that copy an another packets to myself.
 *
 *@param m the pointer to the packet to copy
 *
 *@return a reference to myself
 */
PASER_RESET& PASER_RESET::operator =(const PASER_RESET &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
    destAddress_var.s_addr = m.destAddress_var.s_addr;
    seq = m.seq;

    keyNr = m.keyNr;

    // PASER_RESET
    cert.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.cert.len));
    memcpy(cert.buf, m.cert.buf, (sizeof(uint8_t) * m.cert.len));
    cert.len = m.cert.len;

    sign.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.sign.len));
    memcpy(sign.buf, m.sign.buf, (sizeof(uint8_t) * m.sign.len));
    sign.len = m.sign.len;

    return *this;
}

/**
 * Produces a multi-line description of the packet's contents.
 *
 *@return description of the packet's contents
 */
std::string PASER_RESET::detailedInfo() const {
    std::stringstream out;
    out << "Type: PASER_RESET = " << (int) type << "\n";
    out << " Querying node: " << inet_ntoa(srcAddress_var) << "\n";
    out << " keyNr: " << keyNr << "\n";
    out << " Cert length: " << cert.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " Cert buf: 0x";
        for (int32_t i = 0; i < cert.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) cert.buf[i] << std::dec;
        }
        out << "\n";
    }
    out << " Sign length: " << sign.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " Sign buf: 0x";
        for (int32_t i = 0; i < sign.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) sign.buf[i] << std::dec;
        }
        out << "\n";
    }
    return out.str();
}

/**
 * Creates and return an array of all fields that must be secured with hash or signature
 *
 *@param l length of created array
 *@return packet array
 */
uint8_t * PASER_RESET::toByteArray(int *l) {
    int len = 0;
//    len += 1;
//    len += sizeof(srcAddress_var.s_addr);

    len += sizeof(keyNr);
    len += sizeof(cert.len);
    len += cert.len;

    //messageType
    uint8_t *buf;
    uint8_t *data = (uint8_t *) malloc(len);
    buf = data;
    //messageType
//    data[0] = 0x08;
//    buf ++;

//    //Querying node
//    memcpy(buf, srcAddress_var.s_addr.toString(10), sizeof(srcAddress_var.s_addr));
//    buf += sizeof(srcAddress_var.s_addr);

// Key number
    memcpy(buf, (uint8_t *) &keyNr, sizeof(keyNr));
    buf += sizeof(keyNr);
    memcpy(buf, (uint8_t *) &cert.len, sizeof(cert.len));
    buf += sizeof(cert.len);
    memcpy(buf, cert.buf, cert.len);
    buf += cert.len;

    *l = len;
    return data;
}

/**
 * Creates and return an array of all fields of the package
 *
 *@param l length of created array
 *@return packet array
 */
uint8_t * PASER_RESET::getCompleteByteArray(int *l) {
    int lengthOld = 0;
    uint8_t *tempPacket = toByteArray(&lengthOld);

    int lengthNew = lengthOld;
    lengthNew += 1; //messageType
    lengthNew += sizeof(srcAddress_var.s_addr); //IP of forwarding node
    lengthNew += sizeof(sign.len); // Length of signature
    lengthNew += sign.len; // Signature
    // Allocate block of size "lengthNew" bytes memory.
    uint8_t *data = (uint8_t *) malloc(lengthNew);
    uint8_t *buf;
    buf = data;

    //messageType
    data[0] = 0x08;
    buf++;

    //Querying node
    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
    buf += sizeof(srcAddress_var.s_addr);

    // Packet
    memcpy(buf, tempPacket, lengthOld);
    buf += lengthOld;

    //sign
    memcpy(buf, (uint8_t *) &sign.len, sizeof(sign.len));
    buf += sizeof(sign.len);
    memcpy(buf, sign.buf, sign.len);
    buf += sign.len;

    *l = lengthNew;
    free(tempPacket);
    return data;

//
//    int len = 0;
//    len += 1;
//    len += sizeof(srcAddress_var.s_addr);
//
//    len += sizeof(keyNr);
//    len += sizeof(cert.len);
//    len += cert.len;
//
//    len += sizeof(sign.len);
//    len += sign.len;
//
//    //messageType
//    uint8_t *buf;
//    uint8_t *data = (uint8_t *)malloc(len);
//    buf = data;
//    //messageType
//    data[0] = 0x08;
//    buf ++;
//
//    //Querying node
//    memcpy(buf, (uint8_t *)&srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
//    buf += sizeof(srcAddress_var.s_addr);
//
//    // Key number
//    memcpy(buf, (uint8_t *)&keyNr, sizeof(keyNr));
//    buf += sizeof(keyNr);
//
//    //cert
//    memcpy(buf, (uint8_t *)&cert.len, sizeof(cert.len));
//    buf += sizeof(cert.len);
//    memcpy(buf, cert.buf, cert.len);
//    buf += cert.len;
//
//    //sign
//    memcpy(buf, (uint8_t *)&sign.len, sizeof(sign.len));
//    buf += sizeof(sign.len);
//    memcpy(buf, sign.buf, sign.len);
//    buf += sign.len;
//
//    *l = len;
//    return data;
}

