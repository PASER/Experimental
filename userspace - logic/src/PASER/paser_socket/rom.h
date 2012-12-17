/**
 *\file  		rom
 *@brief       	file defines rom kernel module parameters
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

#ifndef __ROM_H
#define __ROM_H

#define NIPQUAD_BE(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_LE(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

#ifdef __BIG_ENDIAN
#define NIPQUAD(addr) NIPQUAD_BE(addr)
#else /* little endian below */
#define NIPQUAD(addr) NIPQUAD_LE(addr)
#endif /* __BIG_ENDIAN */


enum {
	ROM_C_UNSPEC,
	ROM_C_RREQ,	/* Route Request */
	ROM_C_RLIFE, /* Route Lifetime */
	ROM_C_RTADD,	/* Add Route */
	ROM_C_RTDEL,	/* Delete Route */
	ROM_C_RTDMP,	/* Dump Route Table */
	ROM_C_QREL,	/* Queue Release */
	ROM_C_QDMP,	/* Queue Dump */
	ROM_C_SETGW,	/* Set gw_reachable state */
	ROM_C_RERR,	/* Route Error (Link Layer Feedback) */
	__ROM_C_MAX,
};

enum {
	ROM_A_UNSPEC,
	ROM_A_DST,
	ROM_A_MASK,
	ROM_A_ROUTE,
	ROM_A_GWSTATE,
	ROM_A_ERR_HOST,
	__ROM_A_MAX,
};

#define ROM_A_MAX (__ROM_A_MAX - 1)

enum {
	CAT_UNSPEC,
	CAT_ROUTE,
	CAT_QUEUE,
	CAT_CORE,
	__CAT_MAX,
};

enum {
	CMD_UNSPEC,
	CMD_ROUTE_ADD,
	CMD_ROUTE_DELETE,
	CMD_ROUTE_TIMEOUT,
	CMD_QUEUE_RELEASE,
	CMD_QUEUE_DUMP,
	CMD_CORE_SETGW,
	CMD_CORE_RT_ADD,
	CMD_CORE_RT_DELETE,
	CMD_ROUTE_RT_DUMP,
	__CMD_MAX,
};

enum {
	CMD2_UNSPEC,
	CMD2_VIA,
	CMD2_DEV,
	__CMD2_MAX,
};

#endif	/* __ROM_H */
