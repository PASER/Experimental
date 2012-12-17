/**
 *\class  		PASER_crypto_hash
 *@brief       	Class provides functions to compute and check the hash value of PASER messages.
 *@ingroup		Cryptography
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

class PASER_crypto_hash;

#ifndef PASER_CRYPTO_HASH_H_
#define PASER_CRYPTO_HASH_H_

#include "../config/PASER_defs.h"
#include <openssl/engine.h>

#include "../packet_structure/PASER_TU_RREQ.h"
#include "../packet_structure/PASER_TU_RREP_ACK.h"
#include "../packet_structure/PASER_TU_RREP.h"
#include "../packet_structure/PASER_TB_RERR.h"
#include "../packet_structure/PASER_TB_HELLO.h"

#include "../config/PASER_global.h"

/**
 * Implementation of PASER_crypto_hash classes.
 */
class PASER_crypto_hash {
private:
    PASER_global* pGlobal; // Pointer to global object

public:
    /**
     * Constructor of PASER_crypto_hash Object.
     *
     *@param paser_global Pointer to global object
     *
     *@return nada
     */
    PASER_crypto_hash(PASER_global * paser_global);
    /**
     * Compute a hash value from PASER_TU_RREQ packet and GTK and
     * write the hash value to packet
     *
     *@param packet pointer to the PASER_TU_RREQ packet which will be hashed
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int computeHmacTURREQ(PASER_TU_RREQ * packet, lv_block GTK);

    /**
     * check a hash value from PASER_TU_RREQ packet
     *
     *@param packet pointer to the PASER_TU_RREQ packet which hash will be checked
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int checkHmacTURREQ(PASER_TU_RREQ * packet, lv_block GTK);

    /**
     * Compute a hash value from PASER_TU_RREP packet and GTK and
     * write the hash value to packet
     *
     *@param packet pointer to the PASER_TU_RREP packet which will be hashed
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int computeHmacTURREP(PASER_TU_RREP * packet, lv_block GTK);

    /**
     * check a hash value from PASER_TU_RREP packet
     *
     *@param packet pointer to the PASER_TU_RREP packet which hash will be checked
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int checkHmacTURREP(PASER_TU_RREP * packet, lv_block GTK);

    /**
     * Compute a hash value from PASER_TU_RREPACK packet and GTK and
     * write the hash value to packet
     *
     *@param packet pointer to the PASER_TU_RREPACK packet which will be hashed
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int computeHmacTURREPACK(PASER_TU_RREP_ACK * packet, lv_block GTK);

    /**
     * check a hash value from PASER_TU_RREPACK packet
     *
     *@param packet pointer to the PASER_TU_RREPACK packet which hash will be checked
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int checkHmacTURREPACK(PASER_TU_RREP_ACK * packet, lv_block GTK);

    /**
     * Compute a hash value from PASER_TB_RERR packet and GTK and
     * write the hash value to packet
     *
     *@param packet pointer to the PASER_TB_RERR packet which will be hashed
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int computeHmacRERR(PASER_TB_RERR * packet, lv_block GTK);

    /**
     * check a hash value from PASER_TB_RERR packet
     *
     *@param packet pointer to the PASER_TB_RERR packet which hash will be checked
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int checkHmacRERR(PASER_TB_RERR * packet, lv_block GTK);

    /**
     * Compute a hash value from PASER_TB_HELLO packet and GTK and
     * write the hash value to packet
     *
     *@param packet pointer to the <b>PASER_TB_HELLO</b> packet which will be hashed
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int computeHmacHELLO(PASER_TB_HELLO * packet, lv_block GTK);

    /**
     * check a hash value from PASER_TB_HELLO packet
     *
     *@param packet pointer to the PASER_TB_HELLO packet which hash will be checked
     *@param GTK current GTK
     *
     *@return 1 on successful or 0 on error
     */
    int checkHmacHELLO(PASER_TB_HELLO * packet, lv_block GTK);
};

#endif /* PASER_CRYPTO_HASH_H_ */
