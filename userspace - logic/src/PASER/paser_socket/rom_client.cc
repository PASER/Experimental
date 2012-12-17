/**
 *\class  		rom_client
 *@brief       	Class provides an interface to rom kernel module.
 *
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

#include "rom_client.h"

rom_client::rom_client(PASER_global *paser_global) {
    pGlobal = paser_global;

    sk_rom = nl_socket_alloc();
    if (!sk_rom) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to nl_socket_alloc()\n");
        exit(1);
    }

    genl_connect(sk_rom);
    rom_family = genl_ctrl_resolve(sk_rom, "ROUTE-O-MATIC");

    sk_rtnl = NULL;
    msg_rom = NULL;
    route = NULL;
    rtnl_add_msg_pending = 0;
    rtnl_del_msg_pending = 0;
    rom_msg_pending = 0;
    link_cache = NULL;
    route_cache = NULL;
    cmd = CMD_UNSPEC;
    cat = CAT_UNSPEC;
}

rom_client::~rom_client() {
    if (sk_rom) {
        nl_close(sk_rom);
        nl_socket_free(sk_rom);
    }
}

int rom_client::get_ip_from_arg(const char *src, __u32 *dst) {
    if (inet_pton(AF_INET, src, dst) < 1) {
        printf("inet_pton(): %s is no valid ip address\n", src);
        return -1;
    }
    return 0;
}

int rom_client::arg_is_str(char *arg, char *str) {
    return (strncmp(arg, str, strlen(str) + 1) == 0) ? 1 : 0;
}

void rom_client::create_rom_msg(int type) {
    msg_rom = nlmsg_alloc();
    if (!msg_rom) {
        msg_rom = NULL;
        rom_msg_pending = 0;
        return;
    }

    genlmsg_put(msg_rom, NL_AUTO_PID, NL_AUTO_SEQ, rom_family, 0, NLM_F_CREATE, type, 1);
    rom_msg_pending = 1;
}

void rom_client::rtnl_add_nexthop_via(struct rtnl_route *route, const char *via_addr) {
    struct rtnl_nexthop *nh;
    struct nl_addr *addr;

    nh = rtnl_route_nh_alloc();

    if (!nh) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Out of memory\n");
        return;
    }

    addr = nl_cli_addr_parse(via_addr, rtnl_route_get_family(route));
    rtnl_route_nh_set_gateway(nh, addr);
    nl_addr_put(addr);

    rtnl_route_add_nexthop(route, nh);
}

void rom_client::rtnl_add_nexthop_dev(struct rtnl_route *route, network_device * _device, struct nl_cache *link_cache) {
    struct rtnl_nexthop *nh;
    int ival;

    nh = rtnl_route_nh_alloc();
    if (!nh) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Out of memory\n");
        return;
    }

    ival = rtnl_link_name2i(link_cache, _device->ifname);
    if (!ival) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Device \"%s\" does not exist\n", _device->ifname);
        return;
    }

    rtnl_route_nh_set_ifindex(nh, ival);

    rtnl_route_add_nexthop(route, nh);
}

void rom_client::delete_cb(struct nl_object *obj, void *arg) {
    struct rtnl_route *route = (struct rtnl_route *) obj;
    int err;

    struct nl_sock *__sk_rtnl = (struct nl_sock *) arg;

    err = rtnl_route_delete(__sk_rtnl, route, 0);
    if (err < 0) {
//        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to delete route: %s", nl_geterror(err));
        return;
    }
}

bool rom_client::rom_init(void) {
    int err;

    sk_rtnl = nl_cli_alloc_socket();
    nl_cli_connect(sk_rtnl, NETLINK_ROUTE);

    msg_rom = NULL;

    if ((err = rtnl_link_alloc_cache(sk_rtnl, AF_UNSPEC, &link_cache)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to allocate link cache: %s\n", nl_geterror(err));
        nl_close(sk_rtnl);
        nl_socket_free(sk_rtnl);
        return false;
    }
    nl_cache_mngt_provide(link_cache);

    if ((err = rtnl_route_alloc_cache(sk_rtnl, AF_UNSPEC, 0, &route_cache)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to allocate route cache: %s\n", nl_geterror(err));
        nl_close(sk_rtnl);
        nl_socket_free(sk_rtnl);
        nl_cache_free(link_cache);
        return false;
    }
    nl_cache_mngt_provide(route_cache);

    route = rtnl_route_alloc();
    if (!route) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to allocate route object\n");
        nl_close(sk_rtnl);
        nl_socket_free(sk_rtnl);
        nl_cache_free(link_cache);
        nl_cache_free(route_cache);
        return false;
    }

    return true;
}

void rom_client::rom_nl_cleanup(void) {

    if (sk_rtnl) {
        nl_close(sk_rtnl);
        nl_socket_free(sk_rtnl);
    }
    nl_cache_free(link_cache);
    nl_cache_free(route_cache);

    nl_object_free((struct nl_object *) route);
}

void rom_client::printCMD(int _cat, int _cmd, in_addr destIP, in_addr destMask, int __cmd2, in_addr nextHopIP, network_device *_device) {
    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Send to kernel: ");
    switch (_cat) {
    case CAT_ROUTE:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "route ");
        break;
    case CAT_QUEUE:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "queue ");
        break;
    case CAT_CORE:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "core ");
        break;
    default:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "unknown ");
        break;
    }

    switch (_cmd) {
    case CMD_ROUTE_ADD:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_ROUTE_ADD ");
        break;
    case CMD_ROUTE_DELETE:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_ROUTE_DELETE ");
        break;
    case CMD_ROUTE_RT_DUMP:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_ROUTE_RT_DUMP ");
        break;
    case CMD_ROUTE_TIMEOUT:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_ROUTE_TIMEOUT ");
        break;
    case CMD_QUEUE_RELEASE:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_QUEUE_RELEASE ");
        break;
    case CMD_QUEUE_DUMP:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_QUEUE_DUMP ");
        break;
    case CMD_CORE_SETGW:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_CORE_SETGW ");
        break;
    case CMD_CORE_RT_ADD:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_CORE_RT_ADD ");
        break;
    case CMD_CORE_RT_DELETE:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD_CORE_RT_DELETE ");
        break;
    default:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "unknown ");
        break;
    }

    if (_cmd == CMD_CORE_SETGW) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "%d\n", destIP.s_addr);
        return;
    }
    if ((_cat == CAT_ROUTE && _cmd == CMD_ROUTE_DELETE) || (_cat == CAT_CORE && _cmd == CMD_CORE_RT_DELETE)) {
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "%s ", inet_ntoa(destIP));
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "%s\n", inet_ntoa(destMask));
        return;
    }
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "%s ", inet_ntoa(destIP));
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "%s ", inet_ntoa(destMask));

    switch (__cmd2) {
    case CMD2_VIA:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD2_VIA ");
        break;
    case CMD2_DEV:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "CMD2_DEV ");
        break;
    default:
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, " ");
        break;
    }

    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "%s ", inet_ntoa(nextHopIP));
    if (_device)
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "%s ", _device->ifname);
    PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "\n");

}

int rom_client::addDefaultRoute(in_addr destIP, network_device *_device, int metric) {
    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Add default route. GW: %s. Device: %s. Metric: %d.\n",
            inet_ntoa(destIP), _device->ifname, metric);
    struct rtnl_nexthop *nh;
    int ival;
    int err = 0;

    if (!rom_init())
        return 1;

    /* preparing netlink messages */
    struct nl_addr *addr;
    std::stringstream destAddr;
    destAddr << "0.0.0.0/0";
    /* add route (send rtnl msg) and release queue (send rom msg) */
    rtnl_route_set_family(route, AF_INET);
    addr = nl_cli_addr_parse(destAddr.str().c_str(), rtnl_route_get_family(route));
    if ((err = rtnl_route_set_dst(route, addr)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to set destination address: %s\n", nl_geterror(err));
        rom_nl_cleanup();
        return 1;
    }
    nl_addr_put(addr);

    // allocate nh
    nh = rtnl_route_nh_alloc();
    if (!nh) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Out of memory\n");
        rom_nl_cleanup();
        return 1;
    }

    // set GW IP-address
    addr = nl_cli_addr_parse(inet_ntoa(destIP), rtnl_route_get_family(route));
    rtnl_route_nh_set_gateway(nh, addr);
    nl_addr_put(addr);
    // get if device number
    ival = rtnl_link_name2i(link_cache, _device->ifname);
    if (!ival) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Device \"%s\" does not exist\n", _device->ifname);
        rom_nl_cleanup();
        return 1;
    }
    // set if
    rtnl_route_nh_set_ifindex(nh, ival);
    // set weight
    rtnl_route_nh_set_weight(nh, 64);
    rtnl_route_add_nexthop(route, nh);

//    create_rom_msg(ROM_C_QREL);
//
//    dst_addr = destIP.s_addr;
//    nla_put_u32(msg_rom, ROM_A_DST, dst_addr);

    err = rtnl_route_add(sk_rtnl, route, 0);
    if (err < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to add route: %s\n", nl_geterror(err));
        rom_nl_cleanup();
        return 1;
    }

//    nl_send_auto_complete(sk_rom, msg_rom);

    rom_nl_cleanup();

    return 0;
}

int rom_client::deleteDefaultRoute() {
    PASER_LOG_WRITE_LOG(PASER_LOG_ROUTING_TABLE, "Delete default route\n");
    int err = 0;

    if (!rom_init())
        return 1;

    /* preparing netlink messages */
    struct nl_addr *addr;
    std::stringstream destAddr;
    destAddr << "default/0";
    /* add route (send rtnl msg) and release queue (send rom msg) */
    rtnl_route_set_family(route, AF_INET);
    addr = nl_cli_addr_parse(destAddr.str().c_str(), rtnl_route_get_family(route));
    if ((err = rtnl_route_set_dst(route, addr)) < 0) {
        PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to set destination address: %s\n", nl_geterror(err));
        rom_nl_cleanup();
        return 1;
    }
    nl_addr_put(addr);

    nl_cache_foreach_filter(route_cache, OBJ_CAST(route), delete_cb, sk_rtnl);

    rom_nl_cleanup();

    return 0;
}

int rom_client::send(int _cat, int _cmd, in_addr destIP, in_addr destMask, int _cmd2, in_addr nextHopIP, network_device * _device) {
    printCMD(_cat, _cmd, destIP, destMask, _cmd2, nextHopIP, _device);

    rtnl_add_msg_pending = 0;
    rtnl_del_msg_pending = 0;
    rom_msg_pending = 0;

    __u32 dst_addr;
    int gwstate;
    int err = 0;

    if (!rom_init())
        return 1;

    cat = _cat;

    if (cat == CAT_UNSPEC) {
        rom_nl_cleanup();
        return 1;
    }

    cmd = _cmd;

    /* preparing netlink messages */
    struct nl_addr *addr;
    std::stringstream destAddr;
    int maskSize = 0;
    if (_cmd != CMD_CORE_SETGW) {
        uint32_t maskBit = 1;
        while (maskBit) {
            if (destMask.s_addr & maskBit) {
                maskSize++;
            }
            maskBit = maskBit << 1;
        }
    }
    switch (cmd) {
    case CMD_ROUTE_ADD:
        /* add route (send rtnl msg) and release queue (send rom msg) */
//        nl_cli_route_parse_dst(route, argv[3]);
        destAddr << inet_ntoa(destIP) << "/" << maskSize;
        PASER_LOG_WRITE_LOG_SHORT(PASER_LOG_ROUTING_TABLE, "dest addr = %s\n", destAddr.str().c_str());
        addr = nl_cli_addr_parse(destAddr.str().c_str(), rtnl_route_get_family(route));
        if ((err = rtnl_route_set_dst(route, addr)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to set destination address: %s\n", nl_geterror(err));
            return 1;
        }
        nl_addr_put(addr);

        if (_cmd2 == CMD2_VIA) {
            route_dest_IP.str("");
            route_dest_IP << destAddr;
            route_nextHop_IP.str("");
            route_nextHop_IP << inet_ntoa(destIP);
//            route_device.str("");
//            route_device << _device->ifname;
            rtnl_add_nexthop_via(route, inet_ntoa(nextHopIP));
        } else if (_cmd2 == CMD2_DEV) {
            route_dest_IP.str("");
            route_dest_IP << destAddr;
            route_nextHop_IP.str("");
            route_nextHop_IP << inet_ntoa(nextHopIP);
//            route_device.str("");
            rtnl_add_nexthop_dev(route, _device, link_cache);
        } else {
            err = 1;
        }

        rtnl_add_msg_pending = 1;
        break;

    case CMD_ROUTE_DELETE:
        /* delete route (send rtnl msg) */
//        nl_cli_route_parse_dst(route, argv[3]);
        destAddr << inet_ntoa(destIP) << "/" << maskSize;
        addr = nl_cli_addr_parse(destAddr.str().c_str(), rtnl_route_get_family(route));
        if ((err = rtnl_route_set_dst(route, addr)) < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to set destination address: %s\n", nl_geterror(err));
            return 1;
        }
        nl_addr_put(addr);

        rtnl_del_msg_pending = 1;
        break;

    case CMD_ROUTE_TIMEOUT:
        /* release queue (send rom msg) */
        create_rom_msg(ROM_C_QREL);
        dst_addr = destIP.s_addr;
        nla_put_u32(msg_rom, ROM_A_DST, dst_addr);
        nla_put_u32(msg_rom, ROM_A_MASK, destMask.s_addr);
        break;

    case CMD_QUEUE_RELEASE:
        create_rom_msg(ROM_C_QREL);
        dst_addr = destIP.s_addr;
        nla_put_u32(msg_rom, ROM_A_DST, dst_addr);
        nla_put_u32(msg_rom, ROM_A_MASK, destMask.s_addr);
        break;

    case CMD_QUEUE_DUMP:
        create_rom_msg(ROM_C_QDMP);
        break;

    case CMD_CORE_SETGW:
        create_rom_msg(ROM_C_SETGW);
        gwstate = destIP.s_addr;
        if (gwstate == 0 || gwstate == 1)
            nla_put_u8(msg_rom, ROM_A_GWSTATE, gwstate);
        else
            err = 1;
        break;

    case CMD_CORE_RT_ADD:
        create_rom_msg(ROM_C_RTADD);
        dst_addr = destIP.s_addr;
        nla_put_u32(msg_rom, ROM_A_DST, dst_addr);
        nla_put_u32(msg_rom, ROM_A_MASK, destMask.s_addr);
        break;

    case CMD_CORE_RT_DELETE:
        create_rom_msg(ROM_C_RTDEL);
        dst_addr = destIP.s_addr;
        nla_put_u32(msg_rom, ROM_A_DST, dst_addr);
        nla_put_u32(msg_rom, ROM_A_MASK, destMask.s_addr);

        break;

    case CMD_ROUTE_RT_DUMP:
        create_rom_msg(ROM_C_RTDMP);
        break;

    case CMD_UNSPEC:
        err = 1;
        break;
    }

    if (err != 0) {
        rom_nl_cleanup();
        if (msg_rom) {
            nlmsg_free(msg_rom);
        }
        return EXIT_FAILURE;
    }

    if (rtnl_add_msg_pending) {
        err = rtnl_route_add(sk_rtnl, route, 0);
        if (err < 0) {
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Unable to add route: %s\n", nl_geterror(err));
            rom_nl_cleanup();
            if (msg_rom) {
                nlmsg_free(msg_rom);
            }
            return 1;
        }
    }

    if (rtnl_del_msg_pending) {
        nl_cache_foreach_filter(route_cache, OBJ_CAST(route), delete_cb, sk_rtnl);
    }

    if (rom_msg_pending)
        nl_send_auto_complete(sk_rom, msg_rom);

    rom_nl_cleanup();
    if (msg_rom) {
        nlmsg_free(msg_rom);
    }

    return 0;
}
