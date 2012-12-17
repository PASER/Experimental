/**
 *\class  		rom_client
 *@brief       	Class provides an interface to rom kernel module.
 *@ingroup		Socket
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

class rom_client;

#ifndef ROM_CLIENT
#define ROM_CLIENT

#include "../config/PASER_global.h"
#include "../config/PASER_defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "rom.h"

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/route.h>
#include <netlink/cli/link.h>


class rom_client {
private:
    int cat;
    int cmd;
    struct nl_msg *msg_rom;
    struct nl_sock *sk_rom;
    struct nl_sock *sk_rtnl;
    int rom_family;
    int rom_msg_pending;
    int rtnl_add_msg_pending;
    int rtnl_del_msg_pending;
    struct nl_cache *link_cache;
    struct nl_cache *route_cache;
    struct rtnl_route *route;

    PASER_global *pGlobal;

    std::stringstream route_dest_IP;
    std::stringstream route_nextHop_IP;
//    std::stringstream route_device;
private:
    int get_ip_from_arg(const char *src, __u32 *dst);
    int arg_is_str(char *arg, char *str);
    void create_rom_msg(int type);
    void rtnl_add_nexthop_via(struct rtnl_route *route, const char *via_addr);
    void rtnl_add_nexthop_dev(struct rtnl_route *route, network_device * _device, struct nl_cache *link_cache);
    static void delete_cb(struct nl_object *obj, void *arg);
    bool rom_init(void);
    void rom_nl_cleanup(void);

    void printCMD(int _cat, int _cmd, in_addr destIP, in_addr destMask, int _cmd2, in_addr nextHopIP, network_device *_device);

public:
    rom_client(PASER_global *paser_global);
    ~rom_client();
    int send(int _cat, int _cmd, in_addr destIP, in_addr destMask, int __cmd2, in_addr nextHopIP, network_device *_device);
    int save_delete(in_addr destIP, in_addr destMask, in_addr nextHopIP, network_device *_device);
    int addDefaultRoute(in_addr destIP, network_device *_device, int metric);
    int deleteDefaultRoute();

};

#endif
