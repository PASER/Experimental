/**
 *\file  		PASER_plugin_loader.cpp
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
#include "PASER_plugin_loader.h"
//#include "plugin_util.h"
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include "errno.h"

#include <dlfcn.h>

/* Local functions */
static int init_paser_plugin(struct __paser_plugin*);
static int paser_load_dl(std::string, int);
static int paser_add_dl(struct __paser_plugin*);

std::vector<__paser_plugin> paser_plugin;

extern paserd_conf conf;

/**
 *Function that loads all registered plugins
 *
 *@return the number of plugins loaded
 */
void
paser_load_plugins(void)
{
  int rv = 0;
  for(unsigned int i = 0; i < conf.plugins.size(); i++) {
    if (paser_load_dl(conf.plugins.at(i).name, i) < 0) {
      rv = 1;
    }
  }
  if (rv != 0) {
    //log_message("-- PLUGIN LOADING FAILED! --\n");
    exit(1);
  }
  //log_message(0, "-- ALL PLUGINS LOADED! --\n\n");
}

/**
 *Try to load a shared library and extract
 *the required information
 *
 *@param libname the name of the library(file)
 *
 *@return negative on error
 */
static int
paser_load_dl(std::string libname, int i)
{
  int rv;
  struct __paser_plugin plugin;
  //log_message("---------- LOADING LIBRARY ----------\n");

  plugin.dlhandle = dlopen(libname.c_str(), RTLD_NOW);

  if (plugin.dlhandle == NULL) {
    const int save_errno = errno;
    std::string message;
    message += "DL loading failed:\n";
    message.append(dlerror());
    //log_message(message);
    errno = save_errno;
    return -1;
  }

  rv = paser_add_dl(&plugin);
  if (rv == -1) {
    const int save_errno = errno;
    dlclose(plugin.dlhandle);
    errno = save_errno;
  } else {
    plugin.params.swap(conf.plugins.at(i).params);

    /* Initialize the plugin */
    if (init_paser_plugin(&plugin) != 0) {
      rv = -1;
    }

    /* queue */
    paser_plugin.push_back(plugin);
  }
  
  std::string message;
  message += libname;
  message += (rv == 0 ? "LOADED" : "FAILED");
  //log_message(message);
  return rv;
}

static int
paser_add_dl(struct __paser_plugin *plugin)
{
  get_interface_version_func get_interface_version;
  get_plugin_parameters_func get_plugin_parameters;
  int plugin_interface_version;

  /* Fetch the interface version function, 3 different ways */
  //log_message("Checking plugin interface version: ");
  get_interface_version = (int (*)()) dlsym(plugin->dlhandle, "PASER_plugin_interface_version");
  
  plugin_interface_version = get_interface_version();
  
  if (plugin_interface_version == -1) {
    //log_message(dlerror());
    return -1;
  }
  

  /* Fetch the init function */

  plugin->plugin_init = (int (*)())dlsym(plugin->dlhandle, "PASER_plugin_init");
  if (plugin->plugin_init == NULL) {
     return -1;
  }
  
  get_plugin_parameters = (void (*)(const struct PASER_plugin_parameters **, unsigned int *))dlsym(plugin->dlhandle, "paserd_get_plugin_parameters");
  if (get_plugin_parameters != NULL) {
    (*get_plugin_parameters) (&plugin->plugin_parameters, &plugin->plugin_parameters_size);
  } else {
    return -1;
  }
  return 0;
}

/**
 *Initialize a loaded plugin
 *This includes sending information
 *from PASERd to the plugin and
 *register the functions from the plugin with PASERd
 *
 *@param entry the plugin to initialize
 *
 *@return -1 if there was an error
 */
static int
init_paser_plugin(struct __paser_plugin *entry)
{
  int rv = 0;
//  struct __plugin_param *params;
//  for (unsigned int i = 0; i < entry->params.size(); i++) {
//    if (entry->plugin_parameters_size != 0) {
//      unsigned int i;
//      int rc = 0;
//      for (i = 0; i < entry->plugin_parameters_size; i++) {
//        if (0 == entry->plugin_parameters[i].name[0] || 0 == strcasecmp(entry->plugin_parameters[i].name.c_str(), params->key.c_str())) {
//          /* we have found it! */
//          rc =
//            entry->plugin_parameters[i]._set_plugin_parameter(params->value, entry->plugin_parameters[i].data/*,
//                                                             0 == entry->plugin_parameters[i].name[0]
//                                                             ? (set_plugin_parameter_addon)
//                                                             params->key : entry->plugin_parameters[i].name[0]*/);
////                                                             params->key : entry->plugin_parameters[i].addon);
//          if (rc != 0) {
//            fprintf(stderr, "\nFatal error in plugin parameter \"%s\"/\"%s\"\n", params->key.c_str(), params->value.c_str());
//            rv = -1;
//          }
//          break;
//        }
//      }
//      if (i >= entry->plugin_parameters_size) {
//      } else {
//        if (rc != 0) {
//          rv = -1;
//        }
//      }
//    } else {
//      rv = -1;
//    }
//  }
//
//  entry->plugin_init();
  return rv;
}

/**
 *Close all loaded plugins
 */
void
paser_close_plugins(void)
{
    for (unsigned int i = 0; i < paser_plugin.size(); i++) {
        dlclose(paser_plugin.at(i).dlhandle);
        paser_plugin.at(i).dlhandle = NULL;
  }
}

#endif
