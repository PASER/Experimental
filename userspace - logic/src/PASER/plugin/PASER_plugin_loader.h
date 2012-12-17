/**
 *\file  		PASER_plugin_loader.h
 *@brief       	Under development - Defines function for loading plugins into the PASER daemon
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
#ifdef PLUGIN_LOADER

#ifndef PASER_plugin_loader_H
#define	PASER_plugin_loader_H

#include "PASER_plugin.h"
//#include "logger/logger.h"
//#include "../defs.h"

/* all */
typedef int (*plugin_init_func) (void);
typedef int (*get_interface_version_func) (void);


/* version 1 */
typedef void (*get_plugin_parameters_func) (const struct PASER_plugin_parameters ** params, unsigned int *size);

struct __paser_plugin {
  /* The handle */
  void *dlhandle;

  std::vector<__plugin_param> params;
  int plugin_interface_version;

  plugin_init_func plugin_init;

  /* version 1 */
  const struct PASER_plugin_parameters *plugin_parameters;
  unsigned int plugin_parameters_size;
};

void paser_load_plugins(void);

void paser_close_plugins(void);

int paser_plugin_io(int, void *, size_t);

#endif	/* PASER_plugin_loader_H */


#endif
