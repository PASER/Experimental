/**
 *\class  		PASER_TB_RERR
 *@brief       	Class implements PASER_TB_RERR messages
 *
 *\authors    	Eugen.Paul | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http:///</www.kn.e-technik.tu-dortmund.de/
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

#include "PASER_TB_RERR.h"
#include "../config/PASER_defs.h"

#include <openssl/sha.h>
#include <openssl/x509.h>

/**
 * Constructor of PASER_TB_RERR packet that creates an exact copy of another packets.
 *
 *@param m the pointer to the packet to copy
 */
PASER_TB_RERR::PASER_TB_RERR(const PASER_TB_RERR &m) {
    operator=(m);
}

/**
 * Constructor of PASER_TB_RERR packet that creates a new packet.
 *
 *@param src ip address of sending node
 *@param seqNr sequence number of sending node
 */
PASER_TB_RERR::PASER_TB_RERR(struct in_addr src, u_int32_t seqNr) {
    type = B_RERR;
    srcAddress_var = src;
    destAddress_var = src;
    seq = seqNr;

    keyNr = 0;
}

PASER_TB_RERR::PASER_TB_RERR() {
    type = B_RERR;
    keyNr = 0;
}

PASER_TB_RERR* PASER_TB_RERR::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x05) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of source node
    in_addr tempSrcAddr;
    if ((length + sizeof(tempSrcAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddr.s_addr, pointer, sizeof(tempSrcAddr.s_addr));
    pointer += sizeof(tempSrcAddr.s_addr);
    length += sizeof(tempSrcAddr.s_addr);

    // read Sending node's current sequence number
    u_int32_t tempSeq;
    if ((length + sizeof(tempSeq)) > l) {
        std::cout << "ERROR: Wrong SeqNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSeq, pointer, sizeof(tempSeq));
    pointer += sizeof(tempSeq);
    length += sizeof(tempSeq);

    // read GTK number
    u_int32_t tempKeyNr;
    if ((length + sizeof(tempKeyNr)) > l) {
        std::cout << "ERROR: Wrong KeyNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempKeyNr, pointer, sizeof(tempKeyNr));
    pointer += sizeof(tempKeyNr);
    length += sizeof(tempKeyNr);

    // read length of UnreachableAdressesList
    int tempUnreachableListLength;
    if ((length + sizeof(tempUnreachableListLength)) > l) {
        std::cout << "ERROR: Wrong length of UnreachableAdressesList." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempUnreachableListLength, pointer, sizeof(tempUnreachableListLength));
    pointer += sizeof(tempUnreachableListLength);
    length += sizeof(tempUnreachableListLength);

    // read UnreachableAdressesList
    std::list<unreachableBlock> tempUnreachableAdressesList;
    for (int i = 0; i < tempUnreachableListLength; i++) {
        // read unreachable IP
        in_addr tempIP;
        if ((length + sizeof(tempIP.s_addr)) > l) {
            std::cout << "ERROR: Wrong unreachable IP." << std::endl;
            std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
            return NULL;
        }
        memcpy((uint8_t *) &tempIP.s_addr, pointer, sizeof(tempIP.s_addr));
        pointer += sizeof(tempIP.s_addr);
        length += sizeof(tempIP.s_addr);
        // read sequence of unreachable IP
        int tempSeqIP;
        if ((length + sizeof(tempSeqIP)) > l) {
            std::cout << "ERROR: Wrong Sequence of unreachable IP." << std::endl;
            std::cout << "ERROR: cann't create PASER_TB_RERR packet from given char array." << std::endl;
            return NULL;
        }
        memcpy((uint8_t *) &tempSeqIP, pointer, sizeof(tempSeqIP));
        pointer += sizeof(tempSeqIP);
        length += sizeof(tempSeqIP);

        unreachableBlock tempBlock;
        tempBlock.addr.s_addr = tempIP.s_addr;
        tempBlock.seq = tempSeqIP;
        tempUnreachableAdressesList.push_back(tempBlock);
    }

    // Geographical position of sending node (lat)
    double tempGeoLat;
    if ((length + sizeof(tempGeoLat)) > l) {
        std::cout << "ERROR: Wrong GeoLat." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
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
        return NULL;
    }
    memcpy((uint8_t *) &tempGeoLon, pointer, sizeof(tempGeoLon));
    pointer += sizeof(tempGeoLon);
    length += sizeof(tempGeoLon);

    // read Secret
    u_int8_t * tempSec;
    if ((length + PASER_SECRET_LEN) > l) {
        std::cout << "ERROR: Wrong Secret." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        return NULL;
    }
    tempSec = (uint8_t *) malloc(PASER_SECRET_LEN);
    memcpy((uint8_t *) tempSec, pointer, PASER_SECRET_LEN);
    pointer += PASER_SECRET_LEN;
    length += PASER_SECRET_LEN;

    // read authentication tree length
    int tempAuthListLength;
    if ((length + sizeof(tempAuthListLength)) > l) {
        std::cout << "ERROR: Wrong authentication tree length." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempSec);
        return NULL;
    }
    memcpy((uint8_t *) &tempAuthListLength, pointer, sizeof(tempAuthListLength));
    pointer += sizeof(tempAuthListLength);
    length += sizeof(tempAuthListLength);

    // read authentication tree
    std::list<uint8_t *> tempAuthList;
    for (int i = 0; i < tempAuthListLength; i++) {
        // read authentication tree entry
        u_int8_t * tempEntry;
        if ((length + PASER_SECRET_HASH_LEN) > l) {
            std::cout << "ERROR: Wrong tempEntry. i= " << i << std::endl;
            std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
            free(tempSec);
            for (std::list<uint8_t *>::iterator it = tempAuthList.begin(); it != tempAuthList.end(); it++) {
                u_int8_t * temp = (u_int8_t *) *it;
                free(temp);
            }
            return NULL;
        }
        tempEntry = (uint8_t *) malloc(PASER_SECRET_HASH_LEN);
        memcpy((uint8_t *) tempEntry, pointer, PASER_SECRET_HASH_LEN);
        pointer += PASER_SECRET_HASH_LEN;
        length += PASER_SECRET_HASH_LEN;

        tempAuthList.push_back(tempEntry);
    }

    //read MAC
    u_int8_t * tempMAC;
    if ((length + PASER_SECRET_HASH_LEN) > l) {
        std::cout << "ERROR: Wrong Secret." << std::endl;
        std::cout << "ERROR: cann't create PASER_B_ROOT packet from given char array." << std::endl;
        free(tempSec);
        for (std::list<uint8_t *>::iterator it = tempAuthList.begin(); it != tempAuthList.end(); it++) {
            u_int8_t * temp = (u_int8_t *) *it;
            free(temp);
        }
        return NULL;
    }
    tempMAC = (uint8_t *) malloc(PASER_SECRET_HASH_LEN);
    memcpy((uint8_t *) tempMAC, pointer, PASER_SECRET_HASH_LEN);
    pointer += PASER_SECRET_HASH_LEN;
    length += PASER_SECRET_HASH_LEN;

    PASER_TB_RERR *tempPacket = new PASER_TB_RERR();
    tempPacket->type = B_RERR;
    tempPacket->srcAddress_var.s_addr = tempSrcAddr.s_addr;
    tempPacket->seq = tempSeq;
    tempPacket->UnreachableAdressesList.assign(tempUnreachableAdressesList.begin(), tempUnreachableAdressesList.end());
    tempPacket->geoForwarding.lat = tempGeoLat;
    tempPacket->geoForwarding.lon = tempGeoLon;
    tempPacket->secret = tempSec;
    tempPacket->auth.assign(tempAuthList.begin(), tempAuthList.end());
    tempPacket->hash = tempMAC;
    return tempPacket;
}

/**
 * Destructor
 */
PASER_TB_RERR::~PASER_TB_RERR() {
    free(secret);
    for (std::list<uint8_t *>::iterator it = auth.begin(); it != auth.end(); it++) {
        uint8_t *data = (uint8_t *) *it;
        free(data);
    }
    auth.clear();
    free(hash);
}

/**
 * Function that copy an another packets to myself.
 *
 *@param m the pointer to the packet to copy
 *
 *@return a reference to myself
 */
PASER_TB_RERR& PASER_TB_RERR::operator =(const PASER_TB_RERR &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
    destAddress_var.s_addr = m.destAddress_var.s_addr;
    seq = m.seq;

    keyNr = m.keyNr;

    // PASER_TB_RERR
    std::list<unreachableBlock> tempList(m.UnreachableAdressesList);
    for (std::list<unreachableBlock>::iterator it = tempList.begin(); it != tempList.end(); it++) {
        unreachableBlock temp;
        temp.addr.s_addr = ((unreachableBlock) *it).addr.s_addr;
        temp.seq = ((unreachableBlock) *it).seq;
        UnreachableAdressesList.push_back(temp);
    }

    geoForwarding.lat = m.geoForwarding.lat;
    geoForwarding.lon = m.geoForwarding.lon;

    // secret
    secret = (uint8_t *) malloc((sizeof(uint8_t) * PASER_SECRET_LEN));
    memcpy(secret, m.secret, (sizeof(uint8_t) * PASER_SECRET_LEN));
    // auth
    std::list<uint8_t *> temp(m.auth);
    for (std::list<uint8_t *>::iterator it = temp.begin(); it != temp.end(); it++) {
        uint8_t *data = (uint8_t *) malloc((sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
        memcpy(data, (uint8_t *) *it, (sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
        auth.push_back(data);
    }
    // hash
    hash = (uint8_t *) malloc((sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
    memcpy(hash, m.hash, (sizeof(uint8_t) * SHA256_DIGEST_LENGTH));

    return *this;
}

/**
 * Produces a multi-line description of the packet's contents.
 *
 *@return description of the packet's contents
 */
std::string PASER_TB_RERR::detailedInfo() const {
    std::stringstream out;
    out << "Type: RERR = " << (int) type << "\n";
    out << " Querying node: " << inet_ntoa(srcAddress_var) << "\n";
    out << " Sequence: " << seq << "\n";
    out << " KeyNR: " << keyNr << "\n";
    std::list<unreachableBlock> tempList;
    tempList.assign(UnreachableAdressesList.begin(), UnreachableAdressesList.end());
    out << " unreachable list size: " << tempList.size() << "\n";
    for (std::list<unreachableBlock>::iterator it = tempList.begin(); it != tempList.end(); it++) {
        unreachableBlock tempBlock = (unreachableBlock) *it;
        out << "  - IP: " << inet_ntoa(tempBlock.addr) << ", seq: " << tempBlock.seq << "\n";
    }
    out << " geo.lat: " << geoForwarding.lat << "\n";
    out << " geo.lon: " << geoForwarding.lon << "\n";

    out << " secret: 0x";
    for (int i = 0; i < PASER_SECRET_HASH_LEN; i++) {
        out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) secret[i] << std::dec;
    }
    out << "\n";

    if (conf.LOG_PACKET_INFO_FULL) {
        out << " auth tree:\n";
        std::list<uint8_t *> tempTree;
        tempTree.assign(auth.begin(), auth.end());
        for (std::list<uint8_t *>::iterator it = tempTree.begin(); it != tempTree.end(); it++) {
            uint8_t *tempE = (uint8_t *) *it;
            out << "  0x";
            for (int i = 0; i < PASER_SECRET_HASH_LEN; i++) {
                out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) tempE[i] << std::dec;
            }
            out << "\n";
        }
    }

    if (conf.LOG_PACKET_INFO_FULL) {
        out << " hash: ";
        for (int i = 0; i < PASER_SECRET_HASH_LEN; i++) {
            out << std::hex << (unsigned short) (unsigned char) hash[i] << std::dec;
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
uint8_t * PASER_TB_RERR::toByteArray(int *l) {
    int len = 0;
    len += 1;
    len += sizeof(srcAddress_var.s_addr);
    len += sizeof(seq);
    len += sizeof(keyNr);

    len += sizeof(len); // groesse der UnreachableAdressesList
    for (std::list<unreachableBlock>::iterator it = UnreachableAdressesList.begin(); it != UnreachableAdressesList.end(); it++) {
        unreachableBlock temp = (unreachableBlock) *it;
        len += sizeof(temp.addr.s_addr);
        len += sizeof(temp.seq);
    }

    len += sizeof(geoForwarding.lat);
    len += sizeof(geoForwarding.lon);

    //secret
    len += PASER_SECRET_LEN;

    // auth
    len += sizeof(auth.size());
    for (std::list<uint8_t *>::iterator it = auth.begin(); it != auth.end(); it++) {
        len += SHA256_DIGEST_LENGTH;
    }

    //messageType
    uint8_t *buf;
    uint8_t *data = (uint8_t *) malloc(len);
    buf = data;
    //messageType
    data[0] = 0x05;
    buf++;

    //Querying node
    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
    buf += sizeof(srcAddress_var.s_addr);
    // Sequence number
    memcpy(buf, (uint8_t *) &seq, sizeof(seq));
    buf += sizeof(seq);

    // Key number
    memcpy(buf, (uint8_t *) &keyNr, sizeof(keyNr));
    buf += sizeof(keyNr);
//    // last unreachable Sequence number
//    memcpy(buf, (uint8_t *)&lastUnreachableSeq, sizeof(lastUnreachableSeq));
//    buf += sizeof(lastUnreachableSeq);

    // UnreachableAdressesList
    // Groesse der UnreachableAdressesList
    int tempListSize = UnreachableAdressesList.size();
    memcpy(buf, (uint8_t *) &tempListSize, sizeof(tempListSize));
    buf += sizeof(tempListSize);
    for (std::list<unreachableBlock>::iterator it = UnreachableAdressesList.begin(); it != UnreachableAdressesList.end(); it++) {
        unreachableBlock temp = (unreachableBlock) *it;
        memcpy(buf, (uint8_t *) &temp.addr.s_addr, sizeof(temp.addr.s_addr));
        buf += sizeof(temp.addr.s_addr);
        memcpy(buf, &temp.seq, sizeof(temp.seq));
        buf += sizeof(temp.seq);
    }

    // GEO of forwarding node
    memcpy(buf, (uint8_t *) &geoForwarding.lat, sizeof(geoForwarding.lat));
    buf += sizeof(geoForwarding.lat);
    memcpy(buf, (uint8_t *) &geoForwarding.lon, sizeof(geoForwarding.lon));
    buf += sizeof(geoForwarding.lon);

    // secret
    memcpy(buf, (uint8_t *) secret, (sizeof(uint8_t) * PASER_SECRET_LEN));
    buf += sizeof(uint8_t) * PASER_SECRET_LEN;
    // auth
    int authLen = auth.size();
    memcpy(buf, &authLen, sizeof(authLen));
    buf += sizeof(authLen);
    for (std::list<uint8_t *>::iterator it = auth.begin(); it != auth.end(); it++) {
        memcpy(buf, (uint8_t *) *it, (sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
        buf += sizeof(uint8_t) * SHA256_DIGEST_LENGTH;
    }

    *l = len;
    return data;
}

/**
 * Creates and return an array of all fields of the package
 *
 *@param l length of created array
 *@return packet array
 */
uint8_t * PASER_TB_RERR::getCompleteByteArray(int *l) {
    int lengthOld = 0;
    uint8_t *tempPacket = toByteArray(&lengthOld);

    int lengthNew = lengthOld;
    lengthNew += PASER_SECRET_HASH_LEN; //MAC

    // Allocate block of size "lengthNew" bytes memory.
    uint8_t *data = (uint8_t *) malloc(lengthNew);
    uint8_t *buf;
    buf = data;

    memcpy(buf, tempPacket, lengthOld);
    buf += lengthOld;

    //hash
    memcpy(buf, (uint8_t *) hash, PASER_SECRET_HASH_LEN);
    buf += PASER_SECRET_HASH_LEN;

    *l = lengthNew;
    free(tempPacket);
    return data;
//
//    int len = 0;
//    len += 1;// Type of PASER packets
//    len += sizeof(srcAddress_var.s_addr);// IP address of source node
//    len += sizeof(seq);// Sending node's current sequence number
//    len += sizeof(keyNr); // Key number
//    len += sizeof(len); // Length of UnreachableAdressesList
//    for (std::list<unreachableBlock>::iterator it=UnreachableAdressesList.begin(); it!=UnreachableAdressesList.end(); it++){
//        unreachableBlock temp = (unreachableBlock)*it;
//        len += sizeof(temp.addr.s_addr);
//        len += sizeof(temp.seq);
//    }
//
//    len += sizeof(geoForwarding.lat); // Geographical position of sending node
//    len += sizeof(geoForwarding.lon); // Geographical position of sending node
//
//    len += PASER_SECRET_LEN;//secret
//
//    // auth
//    len += sizeof(auth.size());
//    for(std::list<uint8_t *>::iterator it = auth.begin(); it!=auth.end(); it++){
//        len += SHA256_DIGEST_LENGTH;
//    }
//
//    len += SHA256_DIGEST_LENGTH;//MAC
//
//    //messageType
//    uint8_t *buf;
//    uint8_t *data = (uint8_t *)malloc(len);
//    buf = data;
//    //messageType
//    data[0] = 0x05;
//    buf ++;
//
//    //Querying node
//    memcpy(buf, (uint8_t *)&srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
//    buf += sizeof(srcAddress_var.s_addr);
//    // Sequence number
//    memcpy(buf, (uint8_t *)&seq, sizeof(seq));
//    buf += sizeof(seq);
//    // Key number
//    memcpy(buf, (uint8_t *)&keyNr, sizeof(keyNr));
//    buf += sizeof(keyNr);
//
//    // UnreachableAdressesList
//    // Groesse der UnreachableAdressesList
//    int tempListSize = UnreachableAdressesList.size();
//    memcpy(buf, (uint8_t *)&tempListSize, sizeof(tempListSize));
//    buf += sizeof(tempListSize);
//    for (std::list<unreachableBlock>::iterator it=UnreachableAdressesList.begin(); it!=UnreachableAdressesList.end(); it++){
//        unreachableBlock temp = (unreachableBlock)*it;
//        memcpy(buf, (uint8_t *)&temp.addr.s_addr, sizeof(temp.addr.s_addr));
//        buf += sizeof(temp.addr.s_addr);
//        memcpy(buf, &temp.seq, sizeof(temp.seq));
//        buf += sizeof(temp.seq);
//    }
//
//    // GEO of forwarding node
//    memcpy(buf, (uint8_t *)&geoForwarding.lat, sizeof(geoForwarding.lat));
//    buf += sizeof(geoForwarding.lat);
//    memcpy(buf, (uint8_t *)&geoForwarding.lon, sizeof(geoForwarding.lon));
//    buf += sizeof(geoForwarding.lon);
//
//    // secret
//    memcpy(buf, (uint8_t *)secret, (sizeof(uint8_t) * PASER_SECRET_LEN));
//    buf += sizeof(uint8_t) * PASER_SECRET_LEN;
//    // auth
//    int authLen = auth.size();
//    memcpy(buf, &authLen, sizeof(authLen));
//    buf += sizeof(authLen);
//    for(std::list<uint8_t *>::iterator it = auth.begin(); it!=auth.end(); it++){
//        memcpy(buf, (uint8_t *)*it, (sizeof(uint8_t) * SHA256_DIGEST_LENGTH));
//        buf += sizeof(uint8_t) * SHA256_DIGEST_LENGTH;
//    }
//
//    //hash
//    memcpy(buf, (uint8_t *)hash, SHA256_DIGEST_LENGTH);
//    buf += SHA256_DIGEST_LENGTH;
//
//    *l = len;
//    return data;
}
