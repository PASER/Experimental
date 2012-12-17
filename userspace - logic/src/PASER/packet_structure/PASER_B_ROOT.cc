/**
 *\class  		PASER_B_ROOT
 *@brief       	Class implements PASER_B_ROOT messages
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

#include "PASER_B_ROOT.h"

/**
 * Constructor of PASER_B_ROOT packet that creates an exact copy of another packets.
 *
 *@param m the pointer to the packet to copy
 */
PASER_B_ROOT::PASER_B_ROOT(const PASER_B_ROOT &m) {
    operator=(m);
}

/**
 * Constructor of PASER_B_ROOT packet that creates a new packet.
 *
 *@param src ip address of sending node
 *@param seqNr sequence number of sending node
 */
PASER_B_ROOT::PASER_B_ROOT(struct in_addr src, u_int32_t seqNr) {
    type = B_ROOT;
    srcAddress_var = src;
    destAddress_var = src;
    seq = seqNr;

    sign.buf = NULL;
    sign.len = 0;

    cert.buf = NULL;
    cert.len = 0;

    root = NULL;

    timestamp = 0;
}

PASER_B_ROOT::PASER_B_ROOT() {
    type = B_ROOT;

    sign.buf = NULL;
    sign.len = 0;

    cert.buf = NULL;
    cert.len = 0;

    root = NULL;
}

PASER_B_ROOT* PASER_B_ROOT::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x07) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of source node
    in_addr tempSrcAddr;
    if ((length + sizeof(tempSrcAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddr.s_addr, pointer, sizeof(tempSrcAddr.s_addr));
    pointer += sizeof(tempSrcAddr.s_addr);
    length += sizeof(tempSrcAddr.s_addr);

    // read Sending node's current sequence number
    u_int32_t tempSeq;
    if ((length + sizeof(tempSeq)) > l) {
        std::cout << "ERROR: Wrong SeqNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSeq, pointer, sizeof(tempSeq));
    pointer += sizeof(tempSeq);
    length += sizeof(tempSeq);

    // read Length of Certificate
    u_int32_t tempCertL;
    if ((length + sizeof(tempCertL)) > l) {
        std::cout << "ERROR: Wrong length of certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempCertL, pointer, sizeof(tempCertL));
    pointer += sizeof(tempCertL);
    length += sizeof(tempCertL);

    // read Certificate
    u_int8_t * tempCert;
    if ((length + tempCertL) > l) {
        std::cout << "ERROR: Wrong certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        return NULL;
    }
    tempCert = (uint8_t *) malloc(tempCertL);
    memcpy((uint8_t *) tempCert, pointer, tempCertL);
    pointer += tempCertL;
    length += tempCertL;

    // read Root
    u_int8_t * tempRoot;
    if ((length + PASER_SECRET_HASH_LEN) > l) {
        std::cout << "ERROR: Wrong Root." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempCert);
        return NULL;
    }
    tempRoot = (uint8_t *) malloc(PASER_SECRET_HASH_LEN);
    memcpy((uint8_t *) tempRoot, pointer, PASER_SECRET_HASH_LEN);
    pointer += PASER_SECRET_HASH_LEN;
    length += PASER_SECRET_HASH_LEN;

    // read IV
    u_int32_t tempIV;
    if ((length + sizeof(tempIV)) > l) {
        std::cout << "ERROR: Wrong IV." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempCert);
        free(tempRoot);
        return NULL;
    }
    memcpy((uint8_t *) &tempIV, pointer, sizeof(tempIV));
    pointer += sizeof(tempIV);
    length += sizeof(tempIV);

    // Geographical position of sending node (lat)
    double tempGeoLat;
    if ((length + sizeof(tempGeoLat)) > l) {
        std::cout << "ERROR: Wrong GeoLat." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempCert);
        free(tempRoot);
        return NULL;
    }
    memcpy((uint8_t *) &tempGeoLat, pointer, sizeof(tempGeoLat));
    pointer += sizeof(tempGeoLat);
    length += sizeof(tempGeoLat);

    // read Geographical position of sending node (lon)
    double tempGeoLon;
    if ((length + sizeof(tempGeoLon)) > l) {
        std::cout << "ERROR: Wrong GeoLon." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempCert);
        free(tempRoot);
        return NULL;
    }
    memcpy((uint8_t *) &tempGeoLon, pointer, sizeof(tempGeoLon));
    pointer += sizeof(tempGeoLon);
    length += sizeof(tempGeoLon);

    // read Sending time
    unsigned long tempTime;
    if ((length + sizeof(tempTime)) > l) {
        std::cout << "ERROR: Wrong Timestamp." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempCert);
        free(tempRoot);
        return NULL;
    }
    memcpy((uint8_t *) &tempTime, pointer, sizeof(tempTime));
    pointer += sizeof(tempTime);
    length += sizeof(tempTime);

    // read Length of Signature
    u_int32_t tempSignL;
    if ((length + sizeof(tempSignL)) > l) {
        std::cout << "ERROR: Wrong length of signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempCert);
        free(tempRoot);
        return NULL;
    }
    memcpy((uint8_t *) &tempSignL, pointer, sizeof(tempSignL));
    pointer += sizeof(tempSignL);
    length += sizeof(tempSignL);

    // read Signature
    u_int8_t * tempSign;
    if ((length + tempSignL) > l) {
        std::cout << "ERROR: Wrong signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempCert);
        free(tempRoot);
        return NULL;
    }
    tempSign = (uint8_t *) malloc(tempSignL);
    memcpy((uint8_t *) tempSign, pointer, tempSignL);
    pointer += tempSignL;
    length += tempSignL;

    PASER_B_ROOT *tempPacket = new PASER_B_ROOT();
    tempPacket->type = B_ROOT;
    tempPacket->srcAddress_var.s_addr = tempSrcAddr.s_addr;
    tempPacket->seq = tempSeq;
    tempPacket->cert.len = tempCertL;
    tempPacket->cert.buf = tempCert;
    tempPacket->root = tempRoot;
    tempPacket->initVector = tempIV;
    tempPacket->geoQuerying.lat = tempGeoLat;
    tempPacket->geoQuerying.lon = tempGeoLon;
    tempPacket->timestamp = tempTime;
    tempPacket->sign.len = tempSignL;
    tempPacket->sign.buf = tempSign;
    return tempPacket;
}

/**
 * Destructor
 */
PASER_B_ROOT::~PASER_B_ROOT() {
//    X509 *x;
//    x = (X509*) cert.buf;
    if (cert.len > 0) {
        free(cert.buf);
    }
    free(root);
    if (sign.len > 0) {
        free(sign.buf);
        sign.len = 0;
    }
}

/**
 * Function that copy an another packets to myself.
 *
 *@param m the pointer to the packet to copy
 *
 *@return a reference to myself
 */
PASER_B_ROOT& PASER_B_ROOT::operator =(const PASER_B_ROOT &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
    destAddress_var.s_addr = m.destAddress_var.s_addr;
    seq = m.seq;

    // PASER_B_ROOT
    timestamp = m.timestamp;

    cert.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.cert.len));
    memcpy(cert.buf, m.cert.buf, (sizeof(uint8_t) * m.cert.len));
    cert.len = m.cert.len;

    root = (uint8_t *) malloc((sizeof(uint8_t) * PASER_SECRET_HASH_LEN));
    memcpy(root, m.root, (sizeof(uint8_t) * PASER_SECRET_HASH_LEN));

    initVector = m.initVector;

    geoQuerying.lat = m.geoQuerying.lat;
    geoQuerying.lon = m.geoQuerying.lon;

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
std::string PASER_B_ROOT::detailedInfo() const {
    std::stringstream out;
    out << "Type: PASER_B_ROOT = " << (int) type << "\n";
    out << " Querying node: " << inet_ntoa(srcAddress_var) << "\n";
    out << " Timestamp: " << timestamp << "\n";
    out << " Sequence: " << seq << "\n";
    out << " Cert length: " << cert.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " Cert buf: 0x";
        for (int32_t i = 0; i < cert.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) cert.buf[i] << std::dec;
        }
        out << "\n";
    }
    out << " root: 0x";
    for (int i = 0; i < PASER_SECRET_HASH_LEN; i++) {
        out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) root[i] << std::dec;
    }
    out << "\n";
    out << " initVector: " << initVector << " \n";
    out << " geo.lat: " << geoQuerying.lat << "\n";
    out << " geo.lon: " << geoQuerying.lon << "\n";
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
uint8_t * PASER_B_ROOT::toByteArray(int *l) {
    //Compute length of the packet
    int len = 0;
    len += 1; // Type of PASER packets
    len += sizeof(srcAddress_var.s_addr); // IP address of source node
    len += sizeof(seq); // Sending node's current sequence number

    len += sizeof(cert.len); // Length of Certificate
    len += cert.len; // Certificate

    len += PASER_SECRET_HASH_LEN; // Root element
    len += sizeof(initVector); // IV
    len += sizeof(geoQuerying.lat); // Geographical position of sending node
    len += sizeof(geoQuerying.lon); // Geographical position of sending node
    len += sizeof(timestamp); // Sending time

    // Allocate block of size "len" bytes memory.
    uint8_t *data = (uint8_t *) malloc(len);
    uint8_t *buf;
    buf = data;
    //messageType
    data[0] = 0x07;
    buf++;

    //Querying node
    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
    buf += sizeof(srcAddress_var.s_addr);
    // Sequence number
    memcpy(buf, (uint8_t *) &seq, sizeof(seq));
    buf += sizeof(seq);

    // Cert of querying node
    memcpy(buf, (uint8_t *) &cert.len, sizeof(cert.len));
    buf += sizeof(cert.len);
    memcpy(buf, cert.buf, cert.len);
    buf += cert.len;

    // root
    memcpy(buf, root, PASER_SECRET_HASH_LEN);
    buf += PASER_SECRET_HASH_LEN;
    // IV
    memcpy(buf, (uint8_t *) &initVector, sizeof(initVector));
    buf += sizeof(initVector);
    // GEO of querying node
    memcpy(buf, (uint8_t *) &geoQuerying.lat, sizeof(geoQuerying.lat));
    buf += sizeof(geoQuerying.lat);
    memcpy(buf, (uint8_t *) &geoQuerying.lon, sizeof(geoQuerying.lon));
    buf += sizeof(geoQuerying.lon);
    //timestamp
    memcpy(buf, (uint8_t *) &timestamp, sizeof(timestamp));
    buf += sizeof(timestamp);

    *l = len;
    return data;
}

/**
 * Creates and return an array of all fields of the package
 *
 *@param l length of created array
 *@return packet array
 */
uint8_t * PASER_B_ROOT::getCompleteByteArray(int *l) {
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

//    //Compute full length of the packet
//    int len = 0;
//    len += 1; // Type of PASER packets
//    len += sizeof(srcAddress_var.s_addr); // IP address of source node
//    len += sizeof(seq); // Sending node's current sequence number
//
//    len += sizeof(cert.len); // Length of Certificate
//    len += cert.len; // Certificate
//
//    len += PASER_SECRET_HASH_LEN; // Root element
//    len += sizeof(initVector); // IV
//    len += sizeof(geoQuerying.lat); // Geographical position of sending node
//    len += sizeof(geoQuerying.lon); // Geographical position of sending node
//    len += sizeof(timestamp); // Sending time
//
//    len += sizeof(sign.len); // Length of signature
//    len += sign.len; // Signature
//
//    // Allocate block of size "len" bytes memory.
//    uint8_t *data = (uint8_t *) malloc(len);
//    uint8_t *buf;
//    buf = data;
//    //messageType
//    data[0] = 0x07;
//    buf++;
//
//    //Querying node
//    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
//    buf += sizeof(srcAddress_var.s_addr);
//    // Sequence number
//    memcpy(buf, (uint8_t *) &seq, sizeof(seq));
//    buf += sizeof(seq);
//
//    // Cert of querying node
//    memcpy(buf, (uint8_t *) &cert.len, sizeof(cert.len));
//    buf += sizeof(cert.len);
//    memcpy(buf, cert.buf, cert.len);
//    buf += cert.len;
//
//    // root
//    memcpy(buf, root, PASER_SECRET_HASH_LEN);
//    buf += PASER_SECRET_HASH_LEN;
//    // IV
//    memcpy(buf, (uint8_t *) &initVector, sizeof(initVector));
//    buf += sizeof(initVector);
//    // GEO of querying node
//    memcpy(buf, (uint8_t *) &geoQuerying.lat, sizeof(geoQuerying.lat));
//    buf += sizeof(geoQuerying.lat);
//    memcpy(buf, (uint8_t *) &geoQuerying.lon, sizeof(geoQuerying.lon));
//    buf += sizeof(geoQuerying.lon);
//    //timestamp
//    memcpy(buf, (uint8_t *) &timestamp, sizeof(timestamp));
//    buf += sizeof(timestamp);
//
//    //sign
//    memcpy(buf, (uint8_t *) &sign.len, sizeof(sign.len));
//    buf += sizeof(sign.len);
//    memcpy(buf, sign.buf, sign.len);
//    buf += sign.len;
//
//    *l = len;
//    return data;
}
