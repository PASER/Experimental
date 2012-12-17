/**
 *\class  		PASER_TB_HELLO
 *@brief       	Class implements PASER_TB_HELLO messages
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

#include "PASER_TB_HELLO.h"

#include <openssl/sha.h>
#include <openssl/x509.h>

/**
 * Constructor of PASER_TB_HELLO packet that creates an exact copy of another packets.
 *
 *@param m the pointer to the packet to copy
 */
PASER_TB_HELLO::PASER_TB_HELLO(const PASER_TB_HELLO &m) {
    operator=(m);
}

/**
 * Constructor of PASER_TB_HELLO packet that creates a new packet.
 *
 *@param src ip address of sending node
 *@param seqNr sequence number of sending node
 */
PASER_TB_HELLO::PASER_TB_HELLO(struct in_addr src, u_int32_t seqNr) {
    type = B_HELLO;
    srcAddress_var = src;
    destAddress_var = src;
    seq = seqNr;

    secret = NULL;
    hash = NULL;
}

PASER_TB_HELLO::PASER_TB_HELLO() {
    type = B_HELLO;
    secret = NULL;
    hash = NULL;
}

PASER_TB_HELLO* PASER_TB_HELLO::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x06) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of source node
    in_addr tempSrcAddr;
    if ((length + sizeof(tempSrcAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddr.s_addr, pointer, sizeof(tempSrcAddr.s_addr));
    pointer += sizeof(tempSrcAddr.s_addr);
    length += sizeof(tempSrcAddr.s_addr);

    // read Sending node's current sequence number
    u_int32_t tempSeq;
    if ((length + sizeof(tempSeq)) > l) {
        std::cout << "ERROR: Wrong SeqNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSeq, pointer, sizeof(tempSeq));
    pointer += sizeof(tempSeq);
    length += sizeof(tempSeq);

    // read length of AddressRangeList
    u_int32_t tempAddrRangeListLength;
    if ((length + sizeof(tempAddrRangeListLength)) > l) {
        std::cout << "ERROR: Wrong length of AddressRangeList." << std::endl;
        std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempAddrRangeListLength, pointer, sizeof(tempAddrRangeListLength));
    pointer += sizeof(tempAddrRangeListLength);
    length += sizeof(tempAddrRangeListLength);

    // read AddressRangeList
    std::list<address_list> tempAddressRangeList;
    for (u_int32_t i = 0; i < tempAddrRangeListLength; i++) {
        // read address
        in_addr tempAddr;
        if ((length + sizeof(tempAddr.s_addr)) > l) {
            std::cout << "ERROR: Wrong Addr. i=" << i << std::endl;
            std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
            return NULL;
        }
        memcpy((uint8_t *) &tempAddr.s_addr, pointer, sizeof(tempAddr.s_addr));
        pointer += sizeof(tempAddr.s_addr);
        length += sizeof(tempAddr.s_addr);
        // read subnetwork list length
        u_int32_t tempSubnetworkLength;
        if ((length + sizeof(tempSubnetworkLength)) > l) {
            std::cout << "ERROR: Wrong length of AddressRangeList." << std::endl;
            std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
            return NULL;
        }
        memcpy((uint8_t *) &tempSubnetworkLength, pointer, sizeof(tempSubnetworkLength));
        pointer += sizeof(tempSubnetworkLength);
        length += sizeof(tempSubnetworkLength);

        // read subnetwork
        std::list<address_range> subnetwork;
        for (u_int32_t j = 0; j < tempSubnetworkLength; j++) {
            //read subnetwork IP
            in_addr tempSubnetworkIP;
            if ((length + sizeof(tempSubnetworkIP.s_addr)) > l) {
                std::cout << "ERROR: Wrong Addr. i=" << i << " j= " << j << std::endl;
                std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
                return NULL;
            }
            memcpy((uint8_t *) &tempSubnetworkIP.s_addr, pointer, sizeof(tempSubnetworkIP.s_addr));
            pointer += sizeof(tempSubnetworkIP.s_addr);
            length += sizeof(tempSubnetworkIP.s_addr);
            //read subnetwork MASK
            in_addr tempSubnetworkMask;
            if ((length + sizeof(tempSubnetworkMask.s_addr)) > l) {
                std::cout << "ERROR: Wrong Mask. i=" << i << " j= " << j << std::endl;
                std::cout << "ERROR: cann't create PASER_TB_HELLO packet from given char array." << std::endl;
                return NULL;
            }
            memcpy((uint8_t *) &tempSubnetworkMask.s_addr, pointer, sizeof(tempSubnetworkMask.s_addr));
            pointer += sizeof(tempSubnetworkMask.s_addr);
            length += sizeof(tempSubnetworkMask.s_addr);

            address_range tempAddRange;
            tempAddRange.ipaddr.s_addr = tempSubnetworkIP.s_addr;
            tempAddRange.mask.s_addr = tempSubnetworkMask.s_addr;

            subnetwork.push_back(tempAddRange);
        }

        address_list tempAddrList;
        tempAddrList.ipaddr.s_addr = tempAddr.s_addr;
        tempAddrList.range.assign(subnetwork.begin(), subnetwork.end());
        tempAddressRangeList.push_back(tempAddrList);
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

    PASER_TB_HELLO *tempPacket = new PASER_TB_HELLO();
    tempPacket->type = B_HELLO;
    tempPacket->srcAddress_var.s_addr = tempSrcAddr.s_addr;
    tempPacket->seq = tempSeq;
    tempPacket->AddressRangeList.assign(tempAddressRangeList.begin(), tempAddressRangeList.end());
    tempPacket->geoQuerying.lat = tempGeoLat;
    tempPacket->geoQuerying.lon = tempGeoLon;
    tempPacket->secret = tempSec;
    tempPacket->auth.assign(tempAuthList.begin(), tempAuthList.end());
    tempPacket->hash = tempMAC;
    return tempPacket;
}

/**
 * Destructor
 */
PASER_TB_HELLO::~PASER_TB_HELLO() {
    if (secret != NULL) {
        free(secret);
    }
    for (std::list<uint8_t *>::iterator it = auth.begin(); it != auth.end(); it++) {
        uint8_t *data = (uint8_t *) *it;
        free(data);
    }
    auth.clear();
    if (hash != NULL) {
        free(hash);
    }
}

/**
 * Function that copy an another packets to myself.
 *
 *@param m the pointer to the packet to copy
 *
 *@return a reference to myself
 */
PASER_TB_HELLO& PASER_TB_HELLO::operator =(const PASER_TB_HELLO &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
    destAddress_var.s_addr = m.destAddress_var.s_addr;
    seq = m.seq;

    // PASER_TB_HELLO
    std::list<address_list> tempList(m.AddressRangeList);
    for (std::list<address_list>::iterator it = tempList.begin(); it != tempList.end(); it++) {
        AddressRangeList.push_back((address_list) *it);
    }

    geoQuerying.lat = m.geoQuerying.lat;
    geoQuerying.lon = m.geoQuerying.lon;

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
std::string PASER_TB_HELLO::detailedInfo() const {
    std::stringstream out;
    out << "Type: PASER_TB_HELLO = " << (int) type << "\n";
    out << " Querying node: " << inet_ntoa(srcAddress_var) << "\n";
    out << " Sequence: " << seq << "\n";
    out << " AddL.size: " << AddressRangeList.size() << "\n";
    int i = 0;
    std::list<address_list> tempList;
    tempList.assign(AddressRangeList.begin(), AddressRangeList.end());
    for (std::list<address_list>::iterator it = tempList.begin(); it != tempList.end(); it++) {
        address_list temp = (address_list) *it;
        out << "  " << i << " : " << inet_ntoa(temp.ipaddr) << "\n";
        for (std::list<address_range>::iterator it2 = temp.range.begin(); it2 != temp.range.end(); it2++) {
            out << "     - " << inet_ntoa(((address_range) *it2).ipaddr) << " : ";
            out << inet_ntoa(((address_range) *it2).mask) << "\n";
        }
        i++;
    }
    out << " geo.lat: " << geoQuerying.lat << "\n";
    out << " geo.lon: " << geoQuerying.lon << "\n";

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
            out << std::hex << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) hash[i] << std::dec;
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
uint8_t * PASER_TB_HELLO::toByteArray(int *l) {
    int len = 0;
    len += 1;
    len += sizeof(srcAddress_var.s_addr);
    len += sizeof(seq);

    len += sizeof(len); // groesse der Adl
    for (std::list<address_list>::iterator it = AddressRangeList.begin(); it != AddressRangeList.end(); it++) {
        address_list temp = (address_list) *it;
        len += sizeof(temp.ipaddr.s_addr);
        len += sizeof(len); // groesse der add_r
        for (std::list<address_range>::iterator it2 = temp.range.begin(); it2 != temp.range.end(); it2++) {
            struct in_addr temp_addr;
            temp_addr.s_addr = ((address_range) *it2).ipaddr.s_addr;
            len += sizeof(temp_addr.s_addr);
            temp_addr.s_addr = ((address_range) *it2).mask.s_addr;
            len += sizeof(temp_addr.s_addr);
        }
    }
    len += sizeof(geoQuerying.lat);
    len += sizeof(geoQuerying.lon);

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
    data[0] = 0x06;
    buf++;

    //Querying node
    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
    buf += sizeof(srcAddress_var.s_addr);
    // Sequence number
    memcpy(buf, (uint8_t *) &seq, sizeof(seq));
    buf += sizeof(seq);
    // AddL
    // Groesse der ADL
    int tempListSize = AddressRangeList.size();
    memcpy(buf, (uint8_t *) &tempListSize, sizeof(tempListSize));
    buf += sizeof(tempListSize);
    for (std::list<address_list>::iterator it = AddressRangeList.begin(); it != AddressRangeList.end(); it++) {
        address_list temp = (address_list) *it;
        memcpy(buf, (uint8_t *) &temp.ipaddr.s_addr, sizeof(temp.ipaddr.s_addr));
        buf += sizeof(temp.ipaddr.s_addr);
        // Groesse der address_range
        int tempAdd = temp.range.size();
        memcpy(buf, (uint8_t *) &tempAdd, sizeof(tempAdd));
        buf += sizeof(tempAdd);
        for (std::list<address_range>::iterator it2 = temp.range.begin(); it2 != temp.range.end(); it2++) {
            struct in_addr temp_addr;
            temp_addr.s_addr = ((address_range) *it2).ipaddr.s_addr;
            memcpy(buf, (uint8_t *) &temp_addr.s_addr, sizeof(temp_addr.s_addr));
            buf += sizeof(temp_addr.s_addr);
            temp_addr.s_addr = ((address_range) *it2).mask.s_addr;
            memcpy(buf, (uint8_t *) &temp_addr.s_addr, sizeof(temp_addr.s_addr));
            buf += sizeof(temp_addr.s_addr);
        }
    }
    // GEO of Querying node
    memcpy(buf, (uint8_t *) &geoQuerying.lat, sizeof(geoQuerying.lat));
    buf += sizeof(geoQuerying.lat);
    memcpy(buf, (uint8_t *) &geoQuerying.lon, sizeof(geoQuerying.lon));
    buf += sizeof(geoQuerying.lon);

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
uint8_t * PASER_TB_HELLO::getCompleteByteArray(int *l) {
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
//    len += 1; // Type of PASER packets
//    len += sizeof(srcAddress_var.s_addr); // IP address of source node
//    len += sizeof(seq); // Sending node's current sequence number
//
//    len += sizeof(len); // length of AddressRangeList
//    for (std::list<address_list>::iterator it=AddressRangeList.begin(); it!=AddressRangeList.end(); it++){
//        address_list temp = (address_list)*it;
//        len += sizeof(temp.ipaddr.s_addr);
//        len += sizeof(len); // groesse der add_r
//        for (std::list<address_range>::iterator it2=temp.range.begin(); it2!=temp.range.end(); it2++){
//            struct in_addr temp_addr ;
//            temp_addr.s_addr = ((address_range)*it2).ipaddr.s_addr;
//            len += sizeof(temp_addr.s_addr);
//            temp_addr.s_addr = ((address_range)*it2).mask.s_addr;
//            len += sizeof(temp_addr.s_addr);
//        }
//    }
//    len += sizeof(geoQuerying.lat); // Geographical position of sending node
//    len += sizeof(geoQuerying.lon); // Geographical position of sending node
//
//    len += PASER_SECRET_LEN; // Secret
//
//    // authentication tree
//    len += sizeof(auth.size());
//    for(std::list<uint8_t *>::iterator it = auth.begin(); it!=auth.end(); it++){
//        len += SHA256_DIGEST_LENGTH;
//    }
//
//    len += SHA256_DIGEST_LENGTH; //MAC
//
//    //messageType
//    uint8_t *buf;
//    uint8_t *data = (uint8_t *)malloc(len);
//    buf = data;
//    //messageType
//    data[0] = 0x06;
//    buf ++;
//
//    //Querying node
//    memcpy(buf, (uint8_t *)&srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
//    buf += sizeof(srcAddress_var.s_addr);
//    // Sequence number
//    memcpy(buf, (uint8_t *)&seq, sizeof(seq));
//    buf += sizeof(seq);
//    // AddressRangeList
//    // Groesse der AddressRangeList
//    int tempListSize = AddressRangeList.size();
//    memcpy(buf, (uint8_t *)&tempListSize, sizeof(tempListSize));
//    buf += sizeof(tempListSize);
//    for (std::list<address_list>::iterator it=AddressRangeList.begin(); it!=AddressRangeList.end(); it++){
//        address_list temp = (address_list)*it;
//        memcpy(buf, (uint8_t *)&temp.ipaddr.s_addr, sizeof(temp.ipaddr.s_addr));
//        buf += sizeof(temp.ipaddr.s_addr);
//        // Groesse der address_range
//        int tempAdd = temp.range.size();
//        memcpy(buf, (uint8_t *)&tempAdd, sizeof(tempAdd));
//        buf += sizeof(tempAdd);
//        for (std::list<address_range>::iterator it2=temp.range.begin(); it2!=temp.range.end(); it2++){
//            struct in_addr temp_addr;
//            temp_addr.s_addr = ((address_range)*it2).ipaddr.s_addr;
//            memcpy(buf, (uint8_t *)&temp_addr.s_addr, sizeof(temp_addr.s_addr));
//            buf += sizeof(temp_addr.s_addr);
//            temp_addr.s_addr = ((address_range)*it2).mask.s_addr;
//            memcpy(buf, (uint8_t *)&temp_addr.s_addr, sizeof(temp_addr.s_addr));
//            buf += sizeof(temp_addr.s_addr);
//        }
//    }
//    // GEO of Querying node
//    memcpy(buf, (uint8_t *)&geoQuerying.lat, sizeof(geoQuerying.lat));
//    buf += sizeof(geoQuerying.lat);
//    memcpy(buf, (uint8_t *)&geoQuerying.lon, sizeof(geoQuerying.lon));
//    buf += sizeof(geoQuerying.lon);
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
//    //hash
//    memcpy(buf, (uint8_t *)hash, SHA256_DIGEST_LENGTH);
//    buf += SHA256_DIGEST_LENGTH;
//
//    *l = len;
//    return data;
}
