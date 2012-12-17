/**
 *\class  		PASER_GTKRESET
 *@brief       	Class implements GTK-reset messages
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

#include "PASER_GTKRESET.h"
// #include "../config/PASER_defs.h"

PASER_GTKRESET::PASER_GTKRESET(const PASER_GTKRESET &m) {
    operator=(m);
}

PASER_GTKRESET::PASER_GTKRESET() {
    type = GTKRESET;
}

PASER_GTKRESET::~PASER_GTKRESET() {
    if (cert.len > 0) {
        free(cert.buf);
    }
    if (sign.len > 0) {
        free(sign.buf);
    }
}

PASER_GTKRESET* PASER_GTKRESET::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKRESET packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x0b) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKRESET packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read GTK number
    u_int32_t tempKeyNr;
    if ((length + sizeof(tempKeyNr)) > l) {
        std::cout << "ERROR: Wrong GTK number." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKRESET packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempKeyNr, pointer, sizeof(tempKeyNr));
    pointer += sizeof(tempKeyNr);
    length += sizeof(tempKeyNr);

    // read Length of Certificate
    u_int32_t tempCertL;
    if ((length + sizeof(tempCertL)) > l) {
        std::cout << "ERROR: Wrong length of Certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKRESET packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempCertL, pointer, sizeof(tempCertL));
    pointer += sizeof(tempCertL);
    length += sizeof(tempCertL);

    // read Certificate
    u_int8_t * tempCert;
    if ((length + tempCertL) > l) {
        std::cout << "ERROR: Wrong Certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKRESET packet from given char array." << std::endl;
        return NULL;
    }
    tempCert = (uint8_t *) malloc(tempCertL);
    memcpy((uint8_t *) tempCert, pointer, tempCertL);
    pointer += tempCertL;
    length += tempCertL;

    // read Length of signature
    u_int32_t tempSignL;
    if ((length + sizeof(tempSignL)) > l) {
        std::cout << "ERROR: Wrong length of signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKRESET packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSignL, pointer, sizeof(tempSignL));
    pointer += sizeof(tempSignL);
    length += sizeof(tempSignL);

    // read signature
    u_int8_t * tempSign;
    if ((length + tempSignL) > l) {
        std::cout << "ERROR: Wrong signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKRESET packet from given char array." << std::endl;
        return NULL;
    }
    tempSign = (uint8_t *) malloc(tempSignL);
    memcpy((uint8_t *) tempSign, pointer, tempSignL);
    pointer += tempSignL;
    length += tempSignL;

    PASER_GTKRESET *tempPacket = new PASER_GTKRESET();
    tempPacket->type = GTKRESET;
    tempPacket->keyNr = tempKeyNr;
    tempPacket->cert.len = tempCertL;
    tempPacket->cert.buf = tempCert;
    tempPacket->sign.len = tempSignL;
    tempPacket->sign.buf = tempSign;
    return tempPacket;
}

PASER_GTKRESET& PASER_GTKRESET::operator =(const PASER_GTKRESET &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
//    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
//    destAddress_var.s_addr = m.destAddress_var.s_addr;
//    seq = m.seq;

// PASER_GTKRESET
    keyNr = m.keyNr;

    cert.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.cert.len));
    memcpy(cert.buf, m.cert.buf, (sizeof(uint8_t) * m.cert.len));
    cert.len = m.cert.len;

    sign.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.sign.len));
    memcpy(sign.buf, m.sign.buf, (sizeof(uint8_t) * m.sign.len));
    sign.len = m.sign.len;
    return *this;
}

std::string PASER_GTKRESET::detailedInfo() const {
    std::stringstream out;
    out << "Type: PASER_GTKRESET = " << (int) type << "\n";
    out << " GTK number: " << keyNr << "\n";

    out << " cert length: " << cert.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " cert buf: 0x";
        for (int32_t i = 0; i < cert.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) cert.buf[i] << std::dec;
        }
        out << "\n";
    }

    out << " signature length: " << sign.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " signature buf: 0x";
        for (int32_t i = 0; i < sign.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) sign.buf[i] << std::dec;
        }
        out << "\n";
    }

    return out.str();
}

uint8_t * PASER_GTKRESET::toByteArray(int *l) {
    //Compute length of the packet
    int len = 0;
    len += 1;                // Type of PASER packets

    len += sizeof(keyNr);    // number of GTK

    len += sizeof(cert.len); // Length of Certificate of KDC
    len += cert.len;         // Certificate of KDC

    // Allocate block of size "len" bytes memory.
    uint8_t *data = (uint8_t *) malloc(len);
    uint8_t *buf;
    buf = data;
    //messageType
    data[0] = 0x0b;
    buf++;

    // GTK number
    memcpy(buf, (uint8_t *) &keyNr, sizeof(keyNr));
    buf += sizeof(keyNr);

    // kdc_cert
    memcpy(buf, (uint8_t *) &cert.len, sizeof(cert.len));
    buf += sizeof(cert.len);
    memcpy(buf, cert.buf, cert.len);
    buf += cert.len;

    *l = len;
    return data;
}

uint8_t * PASER_GTKRESET::getCompleteByteArray(int *l) {
    int lengthOld = 0;
    uint8_t *tempPacket = toByteArray(&lengthOld);

    int lengthNew = lengthOld;
    lengthNew += sizeof(sign.len); // Length of signature
    lengthNew += sign.len; // Signature
    // Allocate block of size "lengthNew" bytes memory.
    uint8_t *data = (uint8_t *) malloc(lengthNew);
    uint8_t *buf;
    buf = data;

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
}
