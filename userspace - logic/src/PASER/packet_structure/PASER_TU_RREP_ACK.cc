/**
 *\class  		PASER_TU_RREP_ACK
 *@brief       	Class implements PASER_TU_RREP_ACK messages
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

#include "PASER_TU_RREP_ACK.h"
#include <openssl/sha.h>

/**
 * Constructor of PASER_TU_RREPACK packet that creates an exact copy of another packets.
 *
 *@param m the pointer to the packet to copy
 */
PASER_TU_RREP_ACK::PASER_TU_RREP_ACK(const PASER_TU_RREP_ACK &m) {
    operator=(m);
}

/**
 * Constructor of PASER_TU_RREPACK packet that creates a new packet.
 *
 *@param src ip address of sending node
 *@param dest ip address of querying node
 *@param seqNr sequence number of sending node
 */
PASER_TU_RREP_ACK::PASER_TU_RREP_ACK(struct in_addr src, struct in_addr dest, u_int32_t seqNr) {
    type = TU_RREP_ACK;
    srcAddress_var = src;
    destAddress_var = dest;
    seq = seqNr;

    keyNr = 0;
}

PASER_TU_RREP_ACK::PASER_TU_RREP_ACK() {
    type = TU_RREP_ACK;
}

PASER_TU_RREP_ACK* PASER_TU_RREP_ACK::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREPACK packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x04) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREPACK packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of source node
    in_addr tempSrcAddr;
    if ((length + sizeof(tempSrcAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREPACK packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddr.s_addr, pointer, sizeof(tempSrcAddr.s_addr));
    pointer += sizeof(tempSrcAddr.s_addr);
    length += sizeof(tempSrcAddr.s_addr);

    // read IP address of destination node
    in_addr tempDestAddr;
    if ((length + sizeof(tempDestAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong DestAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREPACK packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempDestAddr.s_addr, pointer, sizeof(tempDestAddr.s_addr));
    pointer += sizeof(tempDestAddr.s_addr);
    length += sizeof(tempDestAddr.s_addr);

    // read Sending node's current sequence number
    u_int32_t tempSeq;
    if ((length + sizeof(tempSeq)) > l) {
        std::cout << "ERROR: Wrong SeqNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREPACK packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSeq, pointer, sizeof(tempSeq));
    pointer += sizeof(tempSeq);
    length += sizeof(tempSeq);

    // read GTK number
    u_int32_t tempKeyNr;
    if ((length + sizeof(tempKeyNr)) > l) {
        std::cout << "ERROR: Wrong KeyNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREPACK packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempKeyNr, pointer, sizeof(tempKeyNr));
    pointer += sizeof(tempKeyNr);
    length += sizeof(tempKeyNr);

    // read Secret
    u_int8_t * tempSec;
    if ((length + PASER_SECRET_LEN) > l) {
        std::cout << "ERROR: Wrong Secret." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREP packet from given char array." << std::endl;
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
        std::cout << "ERROR: cann't create PASER_TU_RREP packet from given char array." << std::endl;
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
            std::cout << "ERROR: cann't create PASER_TU_RREP packet from given char array." << std::endl;
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
        std::cout << "ERROR: cann't create PASER_TU_RREP packet from given char array." << std::endl;
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

    PASER_TU_RREP_ACK *tempPacket = new PASER_TU_RREP_ACK();
    tempPacket->type = TU_RREP_ACK;
    tempPacket->srcAddress_var.s_addr = tempSrcAddr.s_addr;
    tempPacket->destAddress_var.s_addr = tempDestAddr.s_addr;
    tempPacket->seq = tempSeq;
    tempPacket->keyNr = tempKeyNr;
    tempPacket->secret = tempSec;
    tempPacket->auth.assign(tempAuthList.begin(), tempAuthList.end());
    tempPacket->hash = tempMAC;
    return tempPacket;
}

/**
 * Destructor
 */
PASER_TU_RREP_ACK::~PASER_TU_RREP_ACK() {
    for (std::list<uint8_t *>::iterator it = auth.begin(); it != auth.end(); it++) {
        uint8_t *temp = (uint8_t *) *it;
        free(temp);
    }
    free(secret);
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
PASER_TU_RREP_ACK& PASER_TU_RREP_ACK::operator =(const PASER_TU_RREP_ACK &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
    destAddress_var.s_addr = m.destAddress_var.s_addr;
    seq = m.seq;

    keyNr = m.keyNr;

    // PASER_TU_RREPACK
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
std::string PASER_TU_RREP_ACK::detailedInfo() const {
    std::stringstream out;
    out << "Type : TU_RREP_ACK = " << (int) type << "\n";
    out << " Querying node : " << inet_ntoa(srcAddress_var) << "\n";
    out << " Destination node : " << inet_ntoa(destAddress_var) << "\n";
    out << " Sequence : " << seq << "\n";
    out << " KeyNr : " << keyNr << "\n";

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
        out << " hash: 0x";
        for (int i = 0; i < PASER_SECRET_HASH_LEN; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) hash[i] << std::dec;
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
uint8_t * PASER_TU_RREP_ACK::toByteArray(int *l) {
    int len = 0;
    len += 1;
    len += sizeof(srcAddress_var.s_addr);
    len += sizeof(destAddress_var.s_addr);
    len += sizeof(seq);
    len += sizeof(keyNr);

    len += PASER_SECRET_LEN;
    len += sizeof(auth.size());
    len += auth.size() * SHA256_DIGEST_LENGTH;

    //messageType
    uint8_t *buf;
    uint8_t *data = (uint8_t *) malloc(len);
    buf = data;
    //messageType
    data[0] = 0x04;
    buf++;

    //Querying node
    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
    buf += sizeof(srcAddress_var.s_addr);
    //Dest node
    memcpy(buf, (uint8_t *) &destAddress_var.s_addr, sizeof(destAddress_var.s_addr));
    buf += sizeof(destAddress_var.s_addr);
    // Sequence number
    memcpy(buf, (uint8_t *) &seq, sizeof(seq));
    buf += sizeof(seq);
    // Key number
    memcpy(buf, (uint8_t *) &keyNr, sizeof(keyNr));
    buf += sizeof(keyNr);

    // secret
    memcpy(buf, secret, PASER_SECRET_LEN);
    buf += PASER_SECRET_LEN;
    // authentication path
    int authLen = auth.size();
    memcpy(buf, &authLen, sizeof(authLen));
    buf += sizeof(authLen);
    for (std::list<uint8_t *>::iterator it = auth.begin(); it != auth.end(); it++) {
        uint8_t * temp = (uint8_t *) *it;
        memcpy(buf, temp, SHA256_DIGEST_LENGTH);
        buf += SHA256_DIGEST_LENGTH;
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
uint8_t * PASER_TU_RREP_ACK::getCompleteByteArray(int *l) {
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
//    len += 1;
//    len += sizeof(srcAddress_var.s_addr);
//    len += sizeof(destAddress_var.s_addr);
//    len += sizeof(seq);
//    len += sizeof(keyNr);
//
//    len += PASER_SECRET_LEN;
//    len += sizeof(auth.size());
//    len += auth.size() * SHA256_DIGEST_LENGTH;
//
//    len += SHA256_DIGEST_LENGTH;
//
//    //messageType
//    uint8_t *buf;
//    uint8_t *data = (uint8_t *)malloc(len);
//    buf = data;
//    //messageType
//    data[0] = 0x04;
//    buf++;
//
//    //Querying node
//    memcpy(buf, (uint8_t *)&srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
//    buf += sizeof(srcAddress_var.s_addr);
//    //Dest node
//    memcpy(buf, (uint8_t *)&destAddress_var.s_addr, sizeof(destAddress_var.s_addr));
//    buf += sizeof(destAddress_var.s_addr);
//    // Sequence number
//    memcpy(buf, (uint8_t *)&seq, sizeof(seq));
//    buf += sizeof(seq);
//    // Key number
//    memcpy(buf, (uint8_t *)&keyNr, sizeof(keyNr));
//    buf += sizeof(keyNr);
//
//    // secret
//    memcpy(buf, secret, PASER_SECRET_LEN);
//    buf += PASER_SECRET_LEN;
//    // authentication path
//    int authLen = auth.size();
//    memcpy(buf, &authLen, sizeof(authLen));
//    buf += sizeof(authLen);
//    for (std::list<uint8_t *>::iterator it=auth.begin(); it!=auth.end(); it++){
//        uint8_t * temp = (uint8_t *)*it;
//        memcpy(buf, temp, SHA256_DIGEST_LENGTH);
//        buf += SHA256_DIGEST_LENGTH;
//    }
//
//    //hash
//    memcpy(buf, (uint8_t *)hash, SHA256_DIGEST_LENGTH);
//    buf += SHA256_DIGEST_LENGTH;
//
//    *l = len;
//    return data;
}
