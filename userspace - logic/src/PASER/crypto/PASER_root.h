/**
 *\class  		PASER_root
 *@brief       	Class provides function to generate secrets, compute and check authentication trees.
 *@ingroup		Cryptography
 *\authors    	Eugen.Paul | Mohamad.Sbeiti \@paser.info
 *
 *\copyright   (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld)
 *                  at Technische Universitaet Dortmund, Germany
 *                  http:///www.kn.e-technik.tu-dortmund.de/
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

class PASER_root;

#ifndef PASER_ROOT_H_
#define PASER_ROOT_H_

#include <openssl/crypto.h>
#include <list>

#include "../config/PASER_defs.h"
#include "../config/PASER_global.h"

/**
 * Implementation of PASER_root classes.
 */
class PASER_root {
private:
    PASER_global *pGlobal;

    int param;                         ///< number of generated secrets 2^param
    std::list<uint8_t *> secret_list;  ///< list of all generated secrets
    std::list<uint8_t *> tree;         ///< list of computed authentication tree
    uint32_t iv_nr;                    ///< IV
    uint8_t* root_elem;                ///< Root element

    bool authTreeReady;                ///< Is authentication tree generated and ready

public:
    /**
     * Constructor.
     * To generate a authentication tree <b>root_tree</b>
     * must be called
     */
    PASER_root(PASER_global *paser_global);
    ~PASER_root();

    /**
     * initialize the object, generate secrets
     * and compute authentication tree
     *
     *@param n number of generated secrets 2^param
     *
     *@return true on successful or false on error
     */
    bool init(int n);

    /**
     * Generate secrets and compute authentication tree
     *
     *@return true on successful or false on error
     */
    bool regenerate();

    /**
     * Get Root element
     *
     *@return root element
     */
    uint8_t* getRoot();

    /**
     * Get next new and fresh secret
     *
     *@param nr pointer to IV which will be set after the function will be called
     *@param secret pointer to secret which will be set after the function will be called
     *
     *@return authentication path of current secret
     */
    std::list<uint8_t *> getNextSecret(int *nr, uint8_t *secret);

    /**
     * Get IV
     *
     *@return IV
     */
    int getIV();

    /**
     * check authentication path of given secret
     *
     *@param root pointer to the root element of authentication path
     *@param secret pointer to the secret of authentication path
     *@param iv_list authentication path
     *@param iv last IV of the node
     *@param newIV new IV of the node
     *@
     *@return 1 on successful or 0 on error
     */
    int checkRoot( uint8_t* root, uint8_t* secret, std::list<uint8_t *> iv_list, uint32_t iv, uint32_t *newIV );

private:
    /**
     * Calculate authentication tree. All secrets must be generated.
     */
    void calculateTree();

    /**
     * Compute hash
     *
     *@param h1 pointer to char array which will be hashed
     *@param len length of the char array
     *
     *@return hash
     */
    uint8_t* getOneHash(uint8_t* h1, int len);

    /**
     * Compute hash
     *
     *@param h1 pointer to char array which will be hashed
     *@param h2 pointer to char array which will be hashed
     *
     *@return hash
     */
    uint8_t* getHash(uint8_t* h1, uint8_t* h2);

    /**
     * clear list of all generated secrets and list of computed authentication tree
     */
    void clearLists();
};

#endif /* PASER_ROOT_H_ */
