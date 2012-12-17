/**
 *\class  		PASER_GTKREP
 *@brief       	Class implements GTK-response messages
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

#include "PASER_GTKREP.h"
#include "../config/PASER_defs.h"

PASER_GTKREP::PASER_GTKREP(const PASER_GTKREP &m) {
    operator=(m);
}

PASER_GTKREP::PASER_GTKREP() {
    type = GTKREP;
    gtk.len = 0;
    crl.len = 0;
    kdc_cert.len = 0;
    sign_key.len = 0;
    sign_kdc_block.len = 0;
    sign.len = 0;
}

PASER_GTKREP::~PASER_GTKREP() {
    if (gtk.len > 0) {
        free(gtk.buf);
    }
    if (crl.len > 0) {
        free(crl.buf);
    }
    if (kdc_cert.len > 0) {
        free(kdc_cert.buf);
    }
    if (sign_key.len > 0) {
        free(sign_key.buf);
    }
    if (sign_kdc_block.len > 0) {
        free(sign_kdc_block.buf);
    }
    if (sign.len > 0) {
        free(sign.buf);
    }
}

PASER_GTKREP* PASER_GTKREP::create(uint8_t *packet, u_int32_t l) {
    int length = 0;
    uint8_t *pointer;
    pointer = packet;
    if (l < 1) {
        std::cout << "ERROR: Wrong packet length(Length < 1)." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    // read packet type
    if (packet[0] != 0x0a) {
        std::cout << "ERROR: Wrong packet type." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    length++;
    pointer++;

    // read IP address of source node
    in_addr tempSrcAddress;
    if ((length + sizeof(tempSrcAddress.s_addr)) > l) {
        std::cout << "ERROR: Wrong SrcAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSrcAddress.s_addr, pointer, sizeof(tempSrcAddress.s_addr));
    pointer += sizeof(tempSrcAddress.s_addr);
    length += sizeof(tempSrcAddress.s_addr);

    // read IP address of gateway
    in_addr tempGWAddr;
    if ((length + sizeof(tempGWAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong GatewayAddr." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempGWAddr.s_addr, pointer, sizeof(tempGWAddr.s_addr));
    pointer += sizeof(tempGWAddr.s_addr);
    length += sizeof(tempGWAddr.s_addr);

    // read IP address of next hop
    in_addr tempNextHopAddr;
    if ((length + sizeof(tempNextHopAddr.s_addr)) > l) {
        std::cout << "ERROR: Wrong next hop address." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempNextHopAddr.s_addr, pointer, sizeof(tempNextHopAddr.s_addr));
    pointer += sizeof(tempNextHopAddr.s_addr);
    length += sizeof(tempNextHopAddr.s_addr);

    // read Length of GTK
    u_int32_t tempGTKL;
    if ((length + sizeof(tempGTKL)) > l) {
        std::cout << "ERROR: Wrong length of GTK." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempGTKL, pointer, sizeof(tempGTKL));
    pointer += sizeof(tempGTKL);
    length += sizeof(tempGTKL);

    // read GTK
    u_int8_t * tempGTK;
    if ((length + tempGTKL) > l) {
        std::cout << "ERROR: Wrong GTK." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    tempGTK = (uint8_t *) malloc(tempGTKL);
    memcpy((uint8_t *) tempGTK, pointer, tempGTKL);
    pointer += tempGTKL;
    length += tempGTKL;

    // read Sending node's nonce
    u_int32_t tempNonce;
    if ((length + sizeof(tempNonce)) > l) {
        std::cout << "ERROR: Wrong nonce." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempNonce, pointer, sizeof(tempNonce));
    pointer += sizeof(tempNonce);
    length += sizeof(tempNonce);

    // read Length of CRL
    u_int32_t tempCRLL;
    if ((length + sizeof(tempCRLL)) > l) {
        std::cout << "ERROR: Wrong length of CRL." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempCRLL, pointer, sizeof(tempCRLL));
    pointer += sizeof(tempCRLL);
    length += sizeof(tempCRLL);

    // read GTK
    u_int8_t * tempCRL;
    if ((length + tempCRLL) > l) {
        std::cout << "ERROR: Wrong CRL." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    tempCRL = (uint8_t *) malloc(tempCRLL);
    memcpy((uint8_t *) tempCRL, pointer, tempCRLL);
    pointer += tempCRLL;
    length += tempCRLL;

    // read Length of KDC Certificate
    u_int32_t tempKDC_certL;
    if ((length + sizeof(tempKDC_certL)) > l) {
        std::cout << "ERROR: Wrong length of KDC Certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempKDC_certL, pointer, sizeof(tempKDC_certL));
    pointer += sizeof(tempKDC_certL);
    length += sizeof(tempKDC_certL);

    // read KDC Certificate
    u_int8_t * tempKDC_cert;
    if ((length + tempKDC_certL) > l) {
        std::cout << "ERROR: Wrong KDC Certificate." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    tempKDC_cert = (uint8_t *) malloc(tempKDC_certL);
    memcpy((uint8_t *) tempKDC_cert, pointer, tempKDC_certL);
    pointer += tempKDC_certL;
    length += tempKDC_certL;

    // read GTK number
    u_int32_t tempKeyNr;
    if ((length + sizeof(tempKeyNr)) > l) {
        std::cout << "ERROR: Wrong GTK number." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempKeyNr, pointer, sizeof(tempKeyNr));
    pointer += sizeof(tempKeyNr);
    length += sizeof(tempKeyNr);

    // read Length of GTK's signature
    u_int32_t tempSignGTKL;
    if ((length + sizeof(tempSignGTKL)) > l) {
        std::cout << "ERROR: Wrong length of GTK's signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSignGTKL, pointer, sizeof(tempSignGTKL));
    pointer += sizeof(tempSignGTKL);
    length += sizeof(tempSignGTKL);

    // read GTK's signature
    u_int8_t * tempSignGTK;
    if ((length + tempSignGTKL) > l) {
        std::cout << "ERROR: Wrong GTK's signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    tempSignGTK = (uint8_t *) malloc(tempSignGTKL);
    memcpy((uint8_t *) tempSignGTK, pointer, tempSignGTKL);
    pointer += tempSignGTKL;
    length += tempSignGTKL;

    // read Length of signature of KDC block
    u_int32_t tempSignKDCBlockL;
    if ((length + sizeof(tempSignKDCBlockL)) > l) {
        std::cout << "ERROR: Wrong length of signature of KDC block." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSignKDCBlockL, pointer, sizeof(tempSignKDCBlockL));
    pointer += sizeof(tempSignKDCBlockL);
    length += sizeof(tempSignKDCBlockL);

    // read signature of KDC block
    u_int8_t * tempSignKDCBlock;
    if ((length + tempSignKDCBlockL) > l) {
        std::cout << "ERROR: Wrong signature of KDC block." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    tempSignKDCBlock = (uint8_t *) malloc(tempSignKDCBlockL);
    memcpy((uint8_t *) tempSignKDCBlock, pointer, tempSignKDCBlockL);
    pointer += tempSignKDCBlockL;
    length += tempSignKDCBlockL;

    // read Length of signature
    u_int32_t tempSignL;
    if ((length + sizeof(tempSignL)) > l) {
        std::cout << "ERROR: Wrong length of signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    memcpy((uint8_t *) &tempSignL, pointer, sizeof(tempSignL));
    pointer += sizeof(tempSignL);
    length += sizeof(tempSignL);

    // read signature
    u_int8_t * tempSign;
    if ((length + tempSignL) > l) {
        std::cout << "ERROR: Wrong signature." << std::endl;
        std::cout << "ERROR: cann't create PASER_GTKREP packet from given char array." << std::endl;
        return NULL;
    }
    tempSign = (uint8_t *) malloc(tempSignL);
    memcpy((uint8_t *) tempSign, pointer, tempSignL);
    pointer += tempSignL;
    length += tempSignL;

    PASER_GTKREP *tempPacket = new PASER_GTKREP();
    tempPacket->type = GTKREP;
    tempPacket->srcAddress_var.s_addr = tempSrcAddress.s_addr;
    tempPacket->gwAddr.s_addr = tempGWAddr.s_addr;
    tempPacket->nextHopAddr.s_addr = tempNextHopAddr.s_addr;
    tempPacket->gtk.len = tempGTKL;
    tempPacket->gtk.buf = tempGTK;
    tempPacket->nonce = tempNonce;
    tempPacket->crl.len = tempCRLL;
    tempPacket->crl.buf = tempCRL;
    tempPacket->kdc_cert.len = tempKDC_certL;
    tempPacket->kdc_cert.buf = tempKDC_cert;
    tempPacket->kdc_key_nr = tempKeyNr;
    tempPacket->sign_key.len = tempSignGTKL;
    tempPacket->sign_key.buf = tempSignGTK;
    tempPacket->sign_kdc_block.len = tempSignKDCBlockL;
    tempPacket->sign_kdc_block.buf = tempSignKDCBlock;
    tempPacket->sign.len = tempSignL;
    tempPacket->sign.buf = tempSign;
    return tempPacket;
}

PASER_GTKREP& PASER_GTKREP::operator =(const PASER_GTKREP &m) {
    if (this == &m)
        return *this;

    // PASER_MSG
    type = m.type;
    srcAddress_var.s_addr = m.srcAddress_var.s_addr;
//    destAddress_var.s_addr = m.destAddress_var.s_addr;
//    seq = m.seq;

// PASER_GTKREP
    gwAddr.s_addr = m.gwAddr.s_addr;
    nextHopAddr.s_addr = m.nextHopAddr.s_addr;

    gtk.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.gtk.len));
    memcpy(gtk.buf, m.gtk.buf, (sizeof(uint8_t) * m.gtk.len));
    gtk.len = m.gtk.len;

    nonce = m.nonce;

    crl.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.crl.len));
    memcpy(crl.buf, m.crl.buf, (sizeof(uint8_t) * m.crl.len));
    crl.len = m.crl.len;

    kdc_cert.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.kdc_cert.len));
    memcpy(kdc_cert.buf, m.kdc_cert.buf, (sizeof(uint8_t) * m.kdc_cert.len));
    kdc_cert.len = m.kdc_cert.len;

    kdc_key_nr = m.kdc_key_nr;

    sign_key.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.sign_key.len));
    memcpy(sign_key.buf, m.sign_key.buf, (sizeof(uint8_t) * m.sign_key.len));
    sign_key.len = m.sign_key.len;

    sign_kdc_block.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.sign_kdc_block.len));
    memcpy(sign_kdc_block.buf, m.sign_kdc_block.buf, (sizeof(uint8_t) * m.sign_kdc_block.len));
    sign_kdc_block.len = m.sign_kdc_block.len;

    sign.buf = (uint8_t *) malloc((sizeof(uint8_t) * m.sign.len));
    memcpy(sign.buf, m.sign.buf, (sizeof(uint8_t) * m.sign.len));
    sign.len = m.sign.len;
    return *this;
}

std::string PASER_GTKREP::detailedInfo() const {
    std::stringstream out;
    out << "Type: PASER_GTKREP = " << (int) type << "\n";
    out << " IP of Source: " << inet_ntoa(srcAddress_var) << "\n";
    out << " IP of gateway: " << inet_ntoa(gwAddr) << "\n";
    out << " IP of next hop: " << inet_ntoa(nextHopAddr) << "\n";
    out << " GTK length: " << gtk.len << "\n";
    out << " GTK buf: 0x";
    for (int32_t i = 0; i < gtk.len; i++) {
        out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) gtk.buf[i] << std::dec;
    }
    out << "\n";
    out << " Nonce: " << nonce << "\n";
    out << " CRL length: " << crl.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " CRL buf: 0x";
        for (int32_t i = 0; i < crl.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) crl.buf[i] << std::dec;
        }
        out << "\n";
    }
    out << " kdc_cert length: " << kdc_cert.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " kdc_cert buf: 0x";
        for (int32_t i = 0; i < kdc_cert.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) kdc_cert.buf[i] << std::dec;
        }
        out << "\n";
    }
    out << " GTK number: " << kdc_key_nr << "\n";
    out << " GTK's signature length: " << sign_key.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " GTK's signature buf: 0x";
        for (int32_t i = 0; i < sign_key.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) sign_key.buf[i] << std::dec;
        }
        out << "\n";
    }
    out << " signature of KDC Block length: " << sign_kdc_block.len << "\n";
    if (conf.LOG_PACKET_INFO_FULL) {
        out << " signature of KDC Block buf: 0x";
        for (int32_t i = 0; i < sign_kdc_block.len; i++) {
            out << std::hex << std::setw(2) << std::setfill('0') << (unsigned short) (unsigned char) sign_kdc_block.buf[i] << std::dec;
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

uint8_t * PASER_GTKREP::toByteArray(int *l) {
    //Compute length of the packet
    int len = 0;
    len += 1; // Type of PASER packets
    len += sizeof(srcAddress_var.s_addr); // Source's IP address
    len += sizeof(gwAddr.s_addr); // Gateway's IP address
    len += sizeof(nextHopAddr.s_addr); // nextHop's IP address

    len += sizeof(gtk.len); // Length of GTK
    len += gtk.len; // GTK

    len += sizeof(nonce); // Sending node's nonce

    len += sizeof(crl.len); // Length of CRL
    len += crl.len; // CRL

    len += sizeof(kdc_cert.len); // Length of kdc_cert
    len += kdc_cert.len; // kdc_cert

    len += sizeof(kdc_key_nr); // Sending GTK number

    len += sizeof(sign_key.len); // Length of GTK's signature
    len += sign_key.len; // GTK's signature

    len += sizeof(sign_kdc_block.len); // Length of GTK's signature
    len += sign_kdc_block.len; // GTK's signature

    // Allocate block of size "len" bytes memory.
    uint8_t *data = (uint8_t *) malloc(len);
    uint8_t *buf;
    buf = data;
    //messageType
    data[0] = 0x0a;
    buf++;

    //Source's IP address
    memcpy(buf, (uint8_t *) &srcAddress_var.s_addr, sizeof(srcAddress_var.s_addr));
    buf += sizeof(srcAddress_var.s_addr);
    //Gateway's IP address
    memcpy(buf, (uint8_t *) &gwAddr.s_addr, sizeof(gwAddr.s_addr));
    buf += sizeof(gwAddr.s_addr);
    //nextHop's IP address
    memcpy(buf, (uint8_t *) &nextHopAddr.s_addr, sizeof(nextHopAddr.s_addr));
    buf += sizeof(nextHopAddr.s_addr);

    // GTK
    memcpy(buf, (uint8_t *) &gtk.len, sizeof(gtk.len));
    buf += sizeof(gtk.len);
    memcpy(buf, gtk.buf, gtk.len);
    buf += gtk.len;

    // nonce
    memcpy(buf, (uint8_t *) &nonce, sizeof(nonce));
    buf += sizeof(nonce);

    // CRL
    memcpy(buf, (uint8_t *) &crl.len, sizeof(crl.len));
    buf += sizeof(crl.len);
    memcpy(buf, crl.buf, crl.len);
    buf += crl.len;

    // kdc_cert
    memcpy(buf, (uint8_t *) &kdc_cert.len, sizeof(kdc_cert.len));
    buf += sizeof(kdc_cert.len);
    memcpy(buf, kdc_cert.buf, kdc_cert.len);
    buf += kdc_cert.len;

    // GTK number
    memcpy(buf, (uint8_t *) &kdc_key_nr, sizeof(kdc_key_nr));
    buf += sizeof(kdc_key_nr);

    // GTK's signature
    memcpy(buf, (uint8_t *) &sign_key.len, sizeof(sign_key.len));
    buf += sizeof(sign_key.len);
    memcpy(buf, sign_key.buf, sign_key.len);
    buf += sign_key.len;

    // KDC Block's signature
    memcpy(buf, (uint8_t *) &sign_kdc_block.len, sizeof(sign_kdc_block.len));
    buf += sizeof(sign_kdc_block.len);
    memcpy(buf, sign_kdc_block.buf, sign_kdc_block.len);
    buf += sign_kdc_block.len;

    *l = len;
    return data;
}

uint8_t * PASER_GTKREP::getCompleteByteArray(int *l) {
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
