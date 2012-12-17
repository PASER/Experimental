/**
 *\file  		PASER_plugin.h
 *@brief       	Under development - Example plugin for PASER daemon
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

#ifndef PASER_plugin_H
#define	PASER_plugin_H

#include <string>

/**
 * # WARNING: still under development
 * Example plugin for paser daemon
 * Only the bare minimum
 */

/* Define the most recent version */
#define MOST_RECENT_PLUGIN_INTERFACE_VERSION		1
#define LAST_SUPPORTED_PLUGIN_INTERFACE_VERSION		1

/****************************************************************************
 *                Functions that the plugin MUST provide                    *
 ****************************************************************************/


/* We hide them from the compiler here to allow the plugins itself to declare them
 * as they also implement them if we activate -Wredundant-decls.
 * Normally we leave it seen so that we enforce a check by the compiler if they are
 * identical.
 */

/**
 * Plugin interface version
 * Used by main paserd to check plugin interface version
 */
int PASER_plugin_interface_version(void);

/**
 * Initialize plugin
 * Called after all parameters are passed
 */
int PASER_plugin_init(void);

/* Interface version 1 */

/**
 * Register parameters from config file
 * Called for all plugin parameters
 */
int PASER_plugin_register_param(std::string key, std::string value);

typedef int set_plugin_parameter(std::string, std::string);

struct PASER_plugin_parameters {
  std::string name;
  set_plugin_parameter *_set_plugin_parameter;
  void *data;
};

/**
 * Delivers the (address of the) table and the size of the parameter description
 */
void paserd_get_plugin_parameters(const struct PASER_plugin_parameters **params, int *size);


#endif	/* PASER_PLUGIN_H */


