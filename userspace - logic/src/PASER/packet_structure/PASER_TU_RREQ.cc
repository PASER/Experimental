/**
 *\class  		PASER_TU_RREQ
 *@brief       	Class implements PASER_TU_RREQ messages
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

#include "PASER_TU_RREQ.h"
#include <openssl/sha.h>
#include <openssl/x509.h>

/**
 * Constructor of PASER_TU_RREQ packet that creates an exact copy of another packets.
 *
 *@param m the pointer to the packet to copy
 */
PASER_TU_RREQ::PASER_TU_RREQ(const PASER_TU_RREQ &m) {
    operator=(m);
}

/**
 * Constructor of PASER_TU_RREQ packet that creates a new packet.
 *
 *@param src ip address of sending node
 *@param dest ip address of querying node
 *@param seqNr sequence number of sending node
 */
PASER_TU_RREQ::PASER_TU_RREQ(struct in_addr src, struct in_addr dest, u_int32_t seqNr) {
    type = TU_RREQ;
    srcAddress_var = src;
    destAddress_var = dest;
    seq = seqNr;

    keyNr = 0;

    searchGW = 0;
    cert.buf = NULL;
    cert.len = 0;
}

PASER_TU_RREQ::PASER_TU_RREQ() {
    type = TU_RREQ;
    cert.buf = NULL;
    cert.len = 0;
    searchGW = 0;
}

PASER_TU_RREQ* PASER_TU_RREQ::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x02) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of source node
    in_addr tempSrcAddr;
    if ((length + sizeof(tempSrcAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddr.s_addr, pointer, sizeof(tempSrcAddr.s_addr));
    pointer += sizeof(tempSrcAddr.s_addr);
    length += sizeof(tempSrcAddr.s_addr);

    // read IP address of destination node
    in_addr tempDestAddr;
    if ((length + sizeof(tempDestAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong DestAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempDestAddr.s_addr, pointer, sizeof(tempDestAddr.s_addr));
    pointer += sizeof(tempDestAddr.s_addr);
    length += sizeof(tempDestAddr.s_addr);

    // read Sending node's current sequence number
    u_int32_t tempSeq;
    if ((length + sizeof(tempSeq)) > l) {
        std::cout << "ERROR: Wrong SeqNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSeq, pointer, sizeof(tempSeq));
    pointer += sizeof(tempSeq);
    length += sizeof(tempSeq);

    // read GTK number
    u_int32_t tempKeyNr;
    if ((length + sizeof(tempKeyNr)) > l) {
        std::cout << "ERROR: Wrong KeyNr." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempKeyNr, pointer, sizeof(tempKeyNr));
    pointer += sizeof(tempKeyNr);
    length += sizeof(tempKeyNr);

    // read forwarding node's sequence number
    u_int32_t tempSeqForw;
    if ((length + sizeof(tempSeqForw)) > l) {
        std::cout << "ERROR: Wrong SeqForw." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSeqForw, pointer, sizeof(tempSeqForw));
    pointer += sizeof(tempSeqForw);
    length += sizeof(tempSeqForw);

    // read searchGW
    uint8_t tempSearchGW;
    if ((length + sizeof(tempSearchGW)) > l) {
        std::cout << "ERROR: Wrong tempSearchGW." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSearchGW, pointer, sizeof(tempSearchGW));
    length++;
    pointer++;

    // read GFlag
    uint8_t tempGFlag;
    if ((length + sizeof(tempGFlag)) > l) {
        std::cout << "ERROR: Wrong GFlag." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempGFlag, pointer, sizeof(tempGFlag));
    length++;
    pointer++;

    // read length of AddressRangeList
    u_int32_t tempAddrRangeListLength;
    if ((length + sizeof(tempAddrRangeListLength)) > l) {
        std::cout << "ERROR: Wrong length of AddressRangeList." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
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
            std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
            return NULL;
        }
        memcpy((uint8_t *) &tempAddr.s_addr, pointer, sizeof(tempAddr.s_addr));
        pointer += sizeof(tempAddr.s_addr);
        length += sizeof(tempAddr.s_addr);
        // read subnetwork list length
        u_int32_t tempSubnetworkLength;
        if ((length + sizeof(tempSubnetworkLength)) > l) {
            std::cout << "ERROR: Wrong length of AddressRangeList." << std::endl;
            std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
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
                std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
                return NULL;
            }
            memcpy((uint8_t *) &tempSubnetworkIP.s_addr, pointer, sizeof(tempSubnetworkIP.s_addr));
            pointer += sizeof(tempSubnetworkIP.s_addr);
            length += sizeof(tempSubnetworkIP.s_addr);
            //read subnetwork MASK
            in_addr tempSubnetworkMask;
            if ((length + sizeof(tempSubnetworkMask.s_addr)) > l) {
                std::cout << "ERROR: Wrong Mask. i=" << i << " j= " << j << std::endl;
                std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
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

    // read Metric for the route between querying node and forwarding node
    uint8_t tempMetricBetweenQueryingAndForw;
    if ((length + sizeof(tempMetricBetweenQueryingAndForw)) > l) {
        std::cout << "ERROR: Wrong MetricBetweenQueryingAndForw." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempMetricBetweenQueryingAndForw, pointer, sizeof(tempMetricBetweenQueryingAndForw));
    pointer += sizeof(tempMetricBetweenQueryingAndForw);
    length += sizeof(tempMetricBetweenQueryingAndForw);

    u_int32_t tempNonce;
    u_int32_t tempCertL;
    u_int8_t * tempCert;
    if (tempGFlag) {
        // read nonce
        if ((length + sizeof(tempNonce)) > l) {
            std::cout << "ERROR: Wrong nonce." << std::endl;
            std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
            return NULL;
        }
        memcpy((uint8_t *) &tempNonce, pointer, sizeof(tempNonce));
        pointer += sizeof(tempNonce);
        length += sizeof(tempNonce);

        // read Certificate length
        if ((length + sizeof(tempCertL)) > l) {
            std::cout << "ERROR: Wrong length of Certificate." << std::endl;
            std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
            return NULL;
        }
        memcpy((uint8_t *) &tempCertL, pointer, sizeof(tempCertL));
        pointer += sizeof(tempCertL);
        length += sizeof(tempCertL);

        // read Certificate
        if ((length + tempCertL) > l) {
            std::cout << "ERROR: Wrong Certificate." << std::endl;
            std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
            return NULL;
        }
        tempCert = (uint8_t *) malloc(tempCertL);
        memcpy((uint8_t *) tempCert, pointer, tempCertL);
        pointer += tempCertL;
        length += tempCertL;
    }

    // Geographical position of sending node (lat)
    double tempGeoQuerLat;
    if ((length + sizeof(tempGeoQuerLat)) > l) {
        std::cout << "ERROR: Wrong GeoDestLat." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        if (tempGFlag) {
            free(tempCert);
        }
        return NULL;
    }
    memcpy((uint8_t *) &tempGeoQuerLat, pointer, sizeof(tempGeoQuerLat));
    pointer += sizeof(tempGeoQuerLat);
    length += sizeof(tempGeoQuerLat);

    // read Geographical position of sending node (lon)
    double tempGeoQuerLon;
    if ((length + sizeof(tempGeoQuerLon)) > l) {
        std::cout << "ERROR: Wrong GeoDestLon." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        if (tempGFlag) {
            free(tempCert);
        }
        return NULL;
    }
    memcpy((uint8_t *) &tempGeoQuerLon, pointer, sizeof(tempGeoQuerLon));
    pointer += sizeof(tempGeoQuerLon);
    length += sizeof(tempGeoQuerLon);

    // Geographical position of sending node (lat)
    double tempGeoForwLat;
    if ((length + sizeof(tempGeoForwLat)) > l) {
        std::cout << "ERROR: Wrong GeoForwLat." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        if (tempGFlag) {
            free(tempCert);
        }
        return NULL;
    }
    memcpy((uint8_t *) &tempGeoForwLat, pointer, sizeof(tempGeoForwLat));
    pointer += sizeof(tempGeoForwLat);
    length += sizeof(tempGeoForwLat);

    // read Geographical position of sending node (lon)
    double tempGeoForwLon;
    if ((length + sizeof(tempGeoForwLon)) > l) {
        std::cout << "ERROR: Wrong GeoForwLon." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        if (tempGFlag) {
            free(tempCert);
        }
        return NULL;
    }
    memcpy((uint8_t *) &tempGeoForwLon, pointer, sizeof(tempGeoForwLon));
    pointer += sizeof(tempGeoForwLon);
    length += sizeof(tempGeoForwLon);

    // read Secret
    u_int8_t * tempSec;
    if ((length + PASER_SECRET_LEN) > l) {
        std::cout << "ERROR: Wrong Secret." << std::endl;
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        if (tempGFlag) {
            free(tempCert);
        }
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
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        free(tempSec);
        if (tempGFlag) {
            free(tempCert);
        }
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
            std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
            free(tempSec);
            for (std::list<uint8_t *>::iterator it = tempAuthList.begin(); it != tempAuthList.end(); it++) {
                u_int8_t * temp = (u_int8_t *) *it;
                free(temp);
            }
            if (tempGFlag) {
                free(tempCert);
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
        std::cout << "ERROR: cann't create PASER_TU_RREQ packet from given char array." << std::endl;
        free(tempSec);
        for (std::list<uint8_t *>::iterator it = tempAuthList.begin(); it != tempAuthList.end(); it++) {
            u_int8_t * temp = (u_int8_t *) *it;
            free(temp);
        }
        if (tempGFlag) {
            free(tempCert);
        }
        return NULL;
    }
    tempMAC = (uint8_t *) malloc(PASER_SECRET_HASH_LEN);
    memcpy((uint8_t *) tempMAC, pointer, PASER_SECRET_HASH_LEN);
    pointer += PASER_SECRET_HASH_LEN;
    length += PASER_SECRET_HASH_LEN;

    PASER_TU_RREQ *tempPacket = new PASER_TU_RREQ();
    tempPacket->type = TU_RREQ;
    tempPacket->srcAddress_var.s_addr = tempSrcAddr.s_addr;
    tempPacket->destAddress_var.s_addr = tempDestAddr.s_addr;
    tempPacket->seq = tempSeq;
    tempPacket->seqForw = tempSeqForw;
    tempPacket->searchGW = tempSearchGW;
    tempPacket->GFlag = tempGFlag;
    tempPacket->AddressRangeList.assign(tempAddressRangeList.begin(), tempAddressRangeList.end());
    tempPacket->metricBetweenQueryingAndForw = tempMetricBetweenQueryingAndForw;
    if (tempPacket->GFlag) {
        tempPacket->nonce = tempNonce;
        tempPacket->cert.len = tempCertL;
        tempPacket->cert.buf = tempCert;
    }
    tempPacket->geoQuerying.lat = tempGeoQuerLat;
    tempPacket->geoQuerying.lon = tempGeoQuerLon;
    tempPacket->geoForwarding.lat = tempGeoForwLat;
    tempPacket->geoForwarding.lon = tempGeoForwLon;
    tempPacket->keyNr = tempKeyNr;
    tempPacket->secret = tempSec;
    tempPacket->auth.assign(tempAuthList.begin(), tempAuthList.end());
    tempPacket->hash = tempMAC;
    return tempPacket;
}

/**
 * Destructor
 */
PASER_TU_RREQ::~PASER_TU_RREQ() {
    if (GFlag) {
        free(cert.buf);
    }
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
PASER_TU_RREQ& PASER_TU_RREQ::operator =(const PASER_TU_RREQ &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
    destAddress_var.s_addr = m.destAddress_var.s_addr;
    seq = m.seq;
    seqForw = m.seqForw;

    keyNr = m.keyNr;

    // PASER_TU_RREQ
    searchGW = m.searchGW;
    GFlag = m.GFlag;
    std::list<address_list> tempList(m.AddressRangeList);
    for (std::list<address_list>::iterator it = tempList.begin(); it != tempList.end(); it++) {
        AddressRangeList.push_back((address_list) *it);
    }
//    routeFromQueryingToForwarding.assign( m.routeFromQueryingToForwarding.begin(), m.routeFromQueryingToForwarding.end() );
    metricBetweenQueryingAndForw = m.metricBetweenQueryingAndForw;

    if (GFlag) {
        //nonce
        nonce = m.nonce;
        //lv_block cert;
        cert.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.cert.len));
        memcpy(cert.buf, m.cert.buf, (sizeof(uint8_t) * m.cert.len));
        cert.len = m.cert.len;
    }

    geoQuerying.lat = m.geoQuerying.lat;
    geoQuerying.lon = m.geoQuerying.lon;
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
std::string PASER_TU_RREQ::detailedInfo() const {
    std::ostringstream out;
    out << "Type : TURREQ = " << (int) type << "\n";
    out << " Querying node : " << inet_ntoa(srcAddress_var) << "\n";
    out << " Destination node : " << inet_ntoa(destAddress_var) << "\n";
    out << " Sequence : " << seq << "\n";
    out << " Sequence number if forwardig node: " << seqForw << "\n";
    out << " SearchGW : " << (int32_t) searchGW << "\n";
    out << " GFlag : " << (int32_t) GFlag << "\n";
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
    out << " metricBetweenQueryingAndForw : " << (int) metricBetweenQueryingAndForw << "\n";

    if (GFlag) {
        out << "  nonce: " << nonce << "\n";
        out << "  cert length: " << cert.len << "\n";
        if (conf.LOG_PACKET_INFO_FULL) {
            out << "  cert: 0x";
            for (int32_t i = 0; i < cert.len; i++) {
                out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) cert.buf[i] << std::dec;
            }
            out << "\n";
        }
    }

    out << " geoQuerying.lat: " << geoQuerying.lat << "\n";
    out << " geoQuerying.lon: " << geoQuerying.lon << "\n";
    out << " geoForwarding.lat: " << geoForwarding.lat << "\n";
    out << " geoForwarding.lon: " << geoForwarding.lon << "\n";
    out << " KeyNr : " << keyNr << "\n";

    out << " secret: 0x";
    for (int i = 0; i < PASER_SECRET_LEN; i++) {
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
uint8_t * PASER_TU_RREQ::toByteArray(int *l) {
    int len = 0;
    len += 1;
    len += sizeof(srcAddress_var.s_addr);
    len += sizeof(destAddress_var.s_addr);
    len += sizeof(seq);
    len += sizeof(keyNr);
    len += sizeof(seqForw);

    len += sizeof(searchGW);
    len += sizeof(GFlag);
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
    len += sizeof(metricBetweenQueryingAndForw);
    if (GFlag) {
        len += sizeof(nonce);
        len += sizeof(cert.len);
        len += cert.len;
    }
    len += sizeof(geoQuerying.lat);
    len += sizeof(geoQuerying.lon);
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
    data[0] = 0x02;
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

    // Forwarding Sequence number
    memcpy(buf, (uint8_t *) &seqForw, sizeof(seqForw));
    buf += sizeof(seqForw);
    // SearchGW
    if (searchGW)
        buf[0] = 0x01;
    else
        buf[0] = 0x00;
    buf += sizeof(searchGW);
    // GFlag
    if (GFlag)
        buf[0] = 0x01;
    else
        buf[0] = 0x00;
    buf += sizeof(GFlag);
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
    // Metric
    memcpy(buf, (uint8_t *) &metricBetweenQueryingAndForw, sizeof(metricBetweenQueryingAndForw));
    buf += sizeof(metricBetweenQueryingAndForw);
    // Cert of querying node
    if (GFlag) {
        memcpy(buf, (uint8_t *) &nonce, sizeof(nonce));
        buf += sizeof(nonce);
        memcpy(buf, (uint8_t *) &cert.len, sizeof(cert.len));
        buf += sizeof(cert.len);
        memcpy(buf, cert.buf, cert.len);
        buf += cert.len;
    }

    // GEO of querying node
    memcpy(buf, (uint8_t *) &geoQuerying.lat, sizeof(geoQuerying.lat));
    buf += sizeof(geoQuerying.lat);
    memcpy(buf, (uint8_t *) &geoQuerying.lon, sizeof(geoQuerying.lon));
    buf += sizeof(geoQuerying.lon);
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
uint8_t * PASER_TU_RREQ::getCompleteByteArray(int *l) {
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
//    len += sizeof(seqForw);
//
//    len += sizeof(GFlag);
//    len += sizeof(len); // groesse der Adl
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
//    len += sizeof(metricBetweenQueryingAndForw);
//    if (GFlag){
//        len += sizeof(nonce);
//        len += sizeof(cert.len);
//        len += cert.len;
//    }
//    len += sizeof(geoQuerying.lat);
//    len += sizeof(geoQuerying.lon);
//    len += sizeof(geoForwarding.lat);
//    len += sizeof(geoForwarding.lon);
//
//    //secret
//	len += PASER_SECRET_LEN;
//
//    // auth
//    len += sizeof(auth.size());
//    for(std::list<uint8_t *>::iterator it = auth.begin(); it!=auth.end(); it++){
//        len += SHA256_DIGEST_LENGTH;
//    }
//
//    len += SHA256_DIGEST_LENGTH;
//
//    //messageType
//    uint8_t *buf;
//    uint8_t *data = (uint8_t *)malloc(len);
//    buf = data;
//    //messageType
//    data[0] = 0x02;
//    buf ++;
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
//    // Forwarding Sequence number
//    memcpy(buf, (uint8_t *)&seqForw, sizeof(seqForw));
//    buf += sizeof(seqForw);
//    // GFlag
//    if (GFlag)
//        buf[0] = 0x01;
//    else
//        buf[0] = 0x00;
//    buf += sizeof(GFlag);
//    // AddL
//    // Groesse der ADL
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
//    // Metric
//    memcpy(buf, (uint8_t *)&metricBetweenQueryingAndForw, sizeof(metricBetweenQueryingAndForw));
//    buf += sizeof(metricBetweenQueryingAndForw);
//    // Cert of querying node
//    if (GFlag){
//        memcpy(buf, (uint8_t *)&nonce, sizeof(nonce));
//        buf += sizeof(nonce);
//        memcpy(buf, (uint8_t *)&cert.len, sizeof(cert.len));
//        buf += sizeof(cert.len);
//        memcpy(buf, cert.buf, cert.len);
//        buf += cert.len;
//    }
//
//    // GEO of querying node
//    memcpy(buf, (uint8_t *)&geoQuerying.lat, sizeof(geoQuerying.lat));
//    buf += sizeof(geoQuerying.lat);
//    memcpy(buf, (uint8_t *)&geoQuerying.lon, sizeof(geoQuerying.lon));
//    buf += sizeof(geoQuerying.lon);
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
