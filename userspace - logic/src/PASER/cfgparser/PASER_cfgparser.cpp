/**
 *\file  		PASER_cfgparser.cpp
 *@brief       	Configuration-file-parser for PASER daemon
 *\authors    	Eugen.Paul | Mohamad.Sbeiti | Jan.Schroeder \@paser.info
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

#include <string.h>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>
#include <libconfig.h++>

#include "../config/PASER_defs.h"
#include "../config/PASER_global.h"

using namespace libconfig;
using namespace std;

int load_config(string filename, PASER_syslog * tmp_log) {
    Config cfg;
    cfg.setAutoConvert(1);

    extern paserd_conf conf; // declare global paserd_conf-data

    try {
        cfg.readFile(filename.c_str());
    } catch (const FileIOException &fioex) {
        tmp_log->PASER_log(1, "I/O error while reading file.");
        return (EXIT_FAILURE);
    }

    catch (const ParseException &pex) {
        //char message[1000];

        // sprintf(message, "Parse error at %s [LINE %d] - %s", pex.getFile(), pex.getLine(), pex.getError());

        tmp_log->PASER_log(1, "Parse error at %s [LINE %d] - %s", pex.getFile(), pex.getLine(), pex.getError());
        return (EXIT_FAILURE);
    }

    try {
        string value = cfg.lookup("LOG_LVL");
        conf.LOG_LVL = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_LVL' setting in configuration file.");
        conf.LOG_LVL = 5;
    }

    try {
        string value = cfg.lookup("LOG_CONFIGURATION");
        conf.LOG_CONFIGURATION = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_CONFIGURATION' setting in configuration file.");
        conf.LOG_CONFIGURATION = 1;
    }

    try {
        string value = cfg.lookup("LOG_SCHEDULER");
        conf.LOG_SCHEDULER = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_SCHEDULER' setting in configuration file.");
        conf.LOG_SCHEDULER = 3;
    }

    try {
        string value = cfg.lookup("LOG_INIT_MODULES");
        conf.LOG_INIT_MODULES = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_INIT_MODULES' setting in configuration file.");
        conf.LOG_INIT_MODULES = 1;
    }

    try {
        string value = cfg.lookup("LOG_INVALID_PACKET");
        conf.LOG_INVALID_PACKET = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_INVALID_PACKET' setting in configuration file.");
        conf.LOG_INVALID_PACKET = 2;
    }

    try {
        string value = cfg.lookup("LOG_ROUTE_DISCOVERY");
        conf.LOG_ROUTE_DISCOVERY = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_ROUTE_DISCOVERY' setting in configuration file.");
        conf.LOG_ROUTE_DISCOVERY = 2;
    }

    try {
        string value = cfg.lookup("LOG_PACKET_PROCESSING");
        conf.LOG_PACKET_PROCESSING = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_PACKET_PROCESSING' setting in configuration file.");
        conf.LOG_PACKET_PROCESSING = 2;
    }

    try {
        string value = cfg.lookup("LOG_ROUTING_TABLE");
        conf.LOG_ROUTING_TABLE = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_ROUTING_TABLE' setting in configuration file.");
        conf.LOG_ROUTING_TABLE = 2;
    }

    try {
        string value = cfg.lookup("LOG_PACKET_INFO");
        conf.LOG_PACKET_INFO = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_PACKET_INFO' setting in configuration file.");
        conf.LOG_PACKET_INFO = 5;
    }

    try {
        string value = cfg.lookup("LOG_PACKET_INFO_FULL");
        if (atoi(value.c_str()) == 1) {
            conf.LOG_PACKET_INFO_FULL = true;
        } else
            conf.LOG_PACKET_INFO_FULL = false;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_PACKET_INFO_FULL' setting in configuration file.");
        conf.LOG_PACKET_INFO_FULL = false;
    }

    try {
        string value = cfg.lookup("LOG_TIMEOUT_INFO");
        conf.LOG_TIMEOUT_INFO = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_TIMEOUT_INFO' setting in configuration file.");
        conf.LOG_TIMEOUT_INFO = 3;
    }

    try {
        string value = cfg.lookup("LOG_CRYPTO_ERROR");
        conf.LOG_CRYPTO_ERROR = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_CRYPTO_ERROR' setting in configuration file.");
        conf.LOG_CRYPTO_ERROR = 2;
    }

    try {
        string value = cfg.lookup("LOG_ERROR");
        conf.LOG_ERROR = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_ERROR' setting in configuration file.");
        conf.LOG_ERROR = 1;
    }

    try {
        string value = cfg.lookup("LOG_CONNECTION");
        conf.LOG_CONNECTION = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'LOG_CONNECTION' setting in configuration file.");
        conf.LOG_CONNECTION = 1;
    }

    try {
        string value = cfg.lookup("timeDiff");
        conf.timeDiff = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'timeDiff' setting in configuration file.");
        conf.timeDiff = 120;
    }

    try {
        string value = cfg.lookup("IPVersion");
        conf.IPversion = value;
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'IPVersion' setting in configuration file.");
    }

    try {
        string value = cfg.lookup("PASERdPort");
        conf.port = atoi(value.c_str());
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'PASERdPort' setting in configuration file.");
        conf.port = 1653;
    }

    try {
        string value = cfg.lookup("PASER_NUMBER_OF_SECRETS");
        conf.PASER_NUMBER_OF_SECRETS = atoi(value.c_str());
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_NUMBER_OF_SECRETS' setting in configuration file.");
        conf.PASER_NUMBER_OF_SECRETS = 16;
    }

    try {
        string value = cfg.lookup("PASERkdcPort");
        conf.KDCPort = atoi(value.c_str());
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'PASERkdcPort' setting in configuration file.");
        conf.KDCPort = 1654;
    }

    try {
        string value = cfg.lookup("IsGateway");
        if (value.compare("1") == 0 || value.compare("true") == 0) {
            conf.IsGateway = true;
        } else {
            conf.IsGateway = false;
        }
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'IsGateway' setting in configuration file.");
        conf.IsGateway = false;
    }

    try {
        string value = cfg.lookup("PASER_ROUTE_DELETE_TIME");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_ROUTE_DELETE_TIMEOUT;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_ROUTE_DELETE_TIME' setting in configuration file.");
        conf.PASER_CONF_ROUTE_DELETE_TIMEOUT = 90;
    }

    try {
        string value = cfg.lookup("PASER_ROUTE_VALID_TIME");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_ROUTE_VALID_TIMEOUT;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_ROUTE_VALID_TIME' setting in configuration file.");
        conf.PASER_CONF_ROUTE_VALID_TIMEOUT = 80;
    }

    try {
        string value = cfg.lookup("PASER_NEIGHBOR_DELETE_TIME");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_NEIGHBOR_DELETE_TIMEOUT;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_NEIGHBOR_DELETE_TIME' setting in configuration file.");
        conf.PASER_CONF_NEIGHBOR_DELETE_TIMEOUT = 70;
    }

    try {
        string value = cfg.lookup("PASER_NEIGHBOR_VALID_TIME");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_NEIGHBOR_VALID_TIMEOUT;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_NEIGHBOR_VALID_TIME' setting in configuration file.");
        conf.PASER_CONF_NEIGHBOR_VALID_TIMEOUT = 60;
    }

    try {
        string value = cfg.lookup("PASER_TB_HELLO_Interval");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_TB_HELLO_Interval;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_TB_HELLO_Interval' setting in configuration file.");
        conf.PASER_CONF_TB_HELLO_Interval = 20;
    }

    try {
        string value = cfg.lookup("PASER_UB_RREQ_WAIT_TIME");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_UB_RREQ_WAIT_TIME;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_UB_RREQ_WAIT_TIME' setting in configuration file.");
        conf.PASER_CONF_UB_RREQ_WAIT_TIME = 1;
    }

    try {
        string value = cfg.lookup("PASER_UU_RREP_WAIT_TIME");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_UU_RREP_WAIT_TIME;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_UU_RREP_WAIT_TIME' setting in configuration file.");
        conf.PASER_CONF_UU_RREP_WAIT_TIME = 1;
    }

    try {
        string value = cfg.lookup("PASER_UB_RREQ_TRIES");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_UB_RREQ_TRIES;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_UB_RREQ_TRIES' setting in configuration file.");
        conf.PASER_CONF_UB_RREQ_TRIES = 3;
    }

    try {
        string value = cfg.lookup("PASER_UU_RREP_TRIES");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_UU_RREP_TRIES;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_UU_RREP_TRIES' setting in configuration file.");
        conf.PASER_CONF_UU_RREP_TRIES = 3;
    }

    try {
        string value = cfg.lookup("PASER_KDC_REQUEST_TIME");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.PASER_CONF_KDC_REQUEST_TIME;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'PASER_KDC_REQUEST_TIME' setting in configuration file.");
        conf.PASER_CONF_KDC_REQUEST_TIME = 1;
    }

    try {
        string value = cfg.lookup("LOG_ROUTE_MODIFICATION_ADD");
        conf.LOG_ROUTE_MODIFICATION_ADD = atoi(value.c_str());
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'LOG_ROUTE_MODIFICATION_ADD' setting in configuration file.");
        conf.LOG_ROUTE_MODIFICATION_ADD = 0;
    }

    try {
        string value = cfg.lookup("LOG_ROUTE_MODIFICATION_DELETE");
        conf.LOG_ROUTE_MODIFICATION_DELETE = atoi(value.c_str());
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'LOG_ROUTE_MODIFICATION_DELETE' setting in configuration file.");
        conf.LOG_ROUTE_MODIFICATION_DELETE = 0;
    }

    try {
        string value = cfg.lookup("LOG_ROUTE_MODIFICATION_BREAK");
        conf.LOG_ROUTE_MODIFICATION_BREAK = atoi(value.c_str());
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'LOG_ROUTE_MODIFICATION_BREAK' setting in configuration file.");
        conf.LOG_ROUTE_MODIFICATION_BREAK = 0;
    }

    try {
        string value = cfg.lookup("LOG_ROUTE_MODIFICATION_TIMEOUT");
        conf.LOG_ROUTE_MODIFICATION_TIMEOUT = atoi(value.c_str());
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'LOG_ROUTE_MODIFICATION_TIMEOUT' setting in configuration file.");
        conf.LOG_ROUTE_MODIFICATION_TIMEOUT = 0;
    }

    try {
        string value = cfg.lookup("KDCIPAddress");
        conf.KDCIPAddress = value;
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'KDCIPAddress' setting in configuration file. Set KDC IP to 127.0.0.1");
        conf.KDCIPAddress = "127.0.0.1";
    }

    try {
        string value = cfg.lookup("GPS_ENABLE");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.GPS_ENABLE;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'GPS_ENABLE' setting in configuration file.");
        conf.GPS_ENABLE = 1;
    }

    try {
        string value = cfg.lookup("GPS_SERIAL_PORT");
        conf.GPS_SERIAL_PORT = value;
    } catch (const SettingNotFoundException &nfex) {
        tmp_log->PASER_log(1, "No 'GPS_SERIAL_PORT' setting in configuration file. Set KDC IP to 127.0.0.1");
        conf.GPS_SERIAL_PORT = "/dev/ttyS2";
    }

    try {
        string value = cfg.lookup("GPS_SERIAL_SPEED");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.GPS_SERIAL_SPEED;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'GPS_SERIAL_SPEED' setting in configuration file.");
        conf.GPS_SERIAL_SPEED = 4800;
    }

    try {
        string value = cfg.lookup("GPS_MAX_NEIGHBOR_DISTANCE");
        std::istringstream stm;
        stm.str(value);
        stm >> conf.GPS_MAX_NEIGHBOR_DISTANCE;
    } catch (...) {
        tmp_log->PASER_log(1, "No 'GPS_MAX_NEIGHBOR_DISTANCE' setting in configuration file.");
        conf.GPS_MAX_NEIGHBOR_DISTANCE = 250;
    }

    if (conf.GPS_ENABLE == 0) {
        try {
            string value = cfg.lookup("GPS_STATIC_LAT");
            std::istringstream stm;
            stm.str(value);
            stm >> conf.GPS_STATIC_LAT;
        } catch (...) {
            tmp_log->PASER_log(1, "No 'GPS_STATIC_LAT' setting in configuration file.");
            conf.GPS_STATIC_LAT = 0;
        }

        try {
            string value = cfg.lookup("GPS_STATIC_LON");
            std::istringstream stm;
            stm.str(value);
            stm >> conf.GPS_STATIC_LON;
        } catch (...) {
            tmp_log->PASER_log(1, "No 'GPS_STATIC_LON' setting in configuration file.");
            conf.GPS_STATIC_LON = 0;
        }

        try {
            string value = cfg.lookup("GPS_STATIC_ALT");
            std::istringstream stm;
            stm.str(value);
            stm >> conf.GPS_STATIC_ALT;
        } catch (...) {
            tmp_log->PASER_log(1, "No 'GPS_STATIC_ALT' setting in configuration file.");
            conf.GPS_STATIC_ALT = 0;
        }
    }

    const Setting& root = cfg.getRoot();

    try {
        const Setting &interfaces = root["Interfaces"];
        int count = interfaces.getLength();
        conf.interface.clear();

        for (int i = 0; i < count; ++i) {
            const Setting &interface = interfaces[i];

            // Only output the record if all of the expected fields are present.
            string IPv4_addr;

            if (!(interface.lookupValue("IPv4_addr", IPv4_addr)))
                continue;

            __interface new_interface;
            new_interface.name = interfaces[i].getName();
            new_interface.IPv4_addr = IPv4_addr;
            new_interface.IPv4_mask = "255.255.255.255";
            conf.interface.push_back(new_interface);
        }
    } catch (const SettingNotFoundException &nfex) {
        // Ignore.
        tmp_log->PASER_log(1, "END");
    }

    try {
        const Setting &interfaces = root["InterfacesSubnetworks"];
        int count = interfaces.getLength();
        conf.interfaceSubnetwork.clear();

        for (int i = 0; i < count; ++i) {
            const Setting &interface = interfaces[i];

            // Only output the record if all of the expected fields are present.
            string IPv4_addr, IPv4_mask;

            if (!(interface.lookupValue("IPv4_addr", IPv4_addr) && interface.lookupValue("IPv4_mask", IPv4_mask)))
                continue;

            __interface new_interface;
            new_interface.name = interfaces[i].getName();
            new_interface.IPv4_addr = IPv4_addr;
            new_interface.IPv4_mask = IPv4_mask;
            conf.interfaceSubnetwork.push_back(new_interface);
        }
    } catch (const SettingNotFoundException &nfex) {
        // Ignore.
        tmp_log->PASER_log(1, "END");
    }

    try {
        const Setting &plugins = root["LoadPlugins"];
        int count = plugins.getLength();

        // clear plugin list
        conf.plugins.clear();

        for (int i = 0; i < count; ++i) {
            __plugin_entry plugin_entry;
            plugin_entry.name = plugins[i].getName();

            // extract parameters of plugin into plugin_entry
            for (int j = 0; j < plugins[i].getLength(); j++) {
                if (!plugins[i].isList())
                    continue;

                string key = plugins[i][j][0];
                string value = plugins[i][j][1];

                __plugin_param new_parameter;
                new_parameter.key = key;
                new_parameter.value = value;
                plugin_entry.params.push_back(new_parameter);
            }

            // add new plugin into plugin-container
            conf.plugins.push_back(plugin_entry);
        }
    } catch (const SettingNotFoundException &nfex) {
        // Ignore.
        tmp_log->PASER_log(1, "END");
    }

    return EXIT_SUCCESS;
}

string convertInt(int number) {
    stringstream ss; //create a stringstream
    ss << number; //add number to the stream
    return ss.str(); //return a string with the contents of the stream
}

string convertDouble(double number) {
    stringstream ss; //create a stringstream
    ss << number; //add number to the stream
    return ss.str(); //return a string with the contents of the stream
}

void print_conf(PASER_syslog * tmp_log) {
    extern paserd_conf conf;
    string message;

    message += "General Information";
    message += "\n     IPVersion: ";
    message += conf.IPversion;
    message += "\n     PASERd-Port: ";
    message += convertInt(conf.port);
    message += "\n     PASERd-KDCPort: ";
    message += convertInt(conf.KDCPort);
    message += "\n     IsGateway: ";
    if (conf.IsGateway) {
        message += "true";
    } else {
        message += "false";
    }
    message += "\n     KDCIPAddress: ";
    message += conf.KDCIPAddress;

    message += "\n     PASER_NUMBER_OF_SECRETS: ";
    message += convertInt(conf.PASER_NUMBER_OF_SECRETS);
    message += "\n";

    message += "\n     LOG_LVL: ";
    message += convertInt(conf.LOG_LVL);
    message += "\n     LOG_CONFIGURATION: ";
    message += convertInt(conf.LOG_CONFIGURATION);
    message += "\n     LOG_SCHEDULER: ";
    message += convertInt(conf.LOG_SCHEDULER);
    message += "\n     LOG_INIT_MODULES: ";
    message += convertInt(conf.LOG_INIT_MODULES);
    message += "\n     LOG_INVALID_PACKET: ";
    message += convertInt(conf.LOG_INVALID_PACKET);
    message += "\n     LOG_ROUTE_DISCOVERY: ";
    message += convertInt(conf.LOG_ROUTE_DISCOVERY);
    message += "\n     LOG_PACKET_PROCESSING: ";
    message += convertInt(conf.LOG_PACKET_PROCESSING);
    message += "\n     LOG_ROUTING_TABLE: ";
    message += convertInt(conf.LOG_ROUTING_TABLE);
    message += "\n     LOG_PACKET_INFO: ";
    message += convertInt(conf.LOG_PACKET_INFO);
    message += "\n     LOG_PACKET_INFO_FULL: ";
    if(conf.LOG_PACKET_INFO_FULL){
        message += "true";
    }
    else{
        message += "false";
    }
    message += "\n     LOG_TIMEOUT_INFO: ";
    message += convertInt(conf.LOG_TIMEOUT_INFO);
    message += "\n     LOG_CRYPTO_ERROR: ";
    message += convertInt(conf.LOG_CRYPTO_ERROR);
    message += "\n     LOG_ERROR: ";
    message += convertInt(conf.LOG_ERROR);
    message += "\n     LOG_CONNECTION: ";
    message += convertInt(conf.LOG_CONNECTION);
    message += "\n     timeDiff: ";
    message += convertInt(conf.timeDiff);

    message += "\n";

    message += "\n     PASER_CONF_ROUTE_DELETE_TIME: ";
    message += convertDouble(conf.PASER_CONF_ROUTE_DELETE_TIMEOUT);
    message += "\n     PASER_CONF_ROUTE_VALID_TIME: ";
    message += convertDouble(conf.PASER_CONF_ROUTE_VALID_TIMEOUT);
    message += "\n     PASER_CONF_NEIGHBOR_DELETE_TIME: ";
    message += convertDouble(conf.PASER_CONF_NEIGHBOR_DELETE_TIMEOUT);
    message += "\n     PASER_CONF_NEIGHBOR_VALID_TIME: ";
    message += convertDouble(conf.PASER_CONF_NEIGHBOR_VALID_TIMEOUT);
    message += "\n     PASER_CONF_TB_HELLO_Interval: ";
    message += convertDouble(conf.PASER_CONF_TB_HELLO_Interval);
    message += "\n     PASER_CONF_UB_RREQ_WAIT_TIME: ";
    message += convertDouble(conf.PASER_CONF_UB_RREQ_WAIT_TIME);
    message += "\n     PASER_CONF_UU_RREP_WAIT_TIME: ";
    message += convertDouble(conf.PASER_CONF_UU_RREP_WAIT_TIME);
    message += "\n     PASER_CONF_UB_RREQ_TRIES: ";
    message += convertDouble(conf.PASER_CONF_UB_RREQ_TRIES);
    message += "\n     PASER_CONF_UU_RREP_TRIES: ";
    message += convertDouble(conf.PASER_CONF_UU_RREP_TRIES);
    message += "\n     PASER_CONF_KDC_REQUEST_TIME: ";
    message += convertDouble(conf.PASER_CONF_KDC_REQUEST_TIME);

    message += "\n     LOG_ROUTE_MODIFICATION_ADD: ";
    message += convertDouble(conf.LOG_ROUTE_MODIFICATION_ADD);
    message += "\n     LOG_ROUTE_MODIFICATION_DELETE: ";
    message += convertDouble(conf.LOG_ROUTE_MODIFICATION_DELETE);
    message += "\n     LOG_ROUTE_MODIFICATION_BREAK: ";
    message += convertDouble(conf.LOG_ROUTE_MODIFICATION_BREAK);
    message += "\n     LOG_ROUTE_MODIFICATION_TIMEOUT: ";
    message += convertDouble(conf.LOG_ROUTE_MODIFICATION_TIMEOUT);

    message += "\n";

    message += "\n     GPS_ENABLE: ";
    message += convertDouble(conf.GPS_ENABLE);
    message += "\n     GPS_MAX_NEIGHBOR_DISTANCE: ";
    message += convertDouble(conf.GPS_MAX_NEIGHBOR_DISTANCE);
    if (conf.GPS_ENABLE == 0) {
        message += "\n     GPS_STATIC_LAT: ";
        message += convertDouble(conf.GPS_STATIC_LAT);
        message += "\n     GPS_STATIC_LON: ";
        message += convertDouble(conf.GPS_STATIC_LON);
        message += "\n     GPS_STATIC_ALT: ";
        message += convertDouble(conf.GPS_STATIC_ALT);
    }

    message += "\n";

    if (conf.interface.size())
        message += "Interface-Information: \n";
    else
        message += "No interfaces have been added to paserd.conf\n";
    for (unsigned int i = 0; i < conf.interface.size(); i++) {
        message.append(5, ' ');
        message += conf.interface.at(i).name;
        message += "\n     IP-address: ";
        message += conf.interface.at(i).IPv4_addr;
        message += "\n     IP-Mask   : ";
        message += conf.interface.at(i).IPv4_mask;
        message += "\n\n";
    }

    if (conf.interfaceSubnetwork.size())
        message += "Interface-Information: \n";
    else
        message += "No subnetwork interfaces have been added to paserd.conf\n";
    for (unsigned int i = 0; i < conf.interfaceSubnetwork.size(); i++) {
        message.append(5, ' ');
        message += conf.interfaceSubnetwork.at(i).name;
        message += "\n     IP-address: ";
        message += conf.interfaceSubnetwork.at(i).IPv4_addr;
        message += "\n     IP-Mask   : ";
        message += conf.interfaceSubnetwork.at(i).IPv4_mask;
        message += "\n\n";
    }

    if (conf.plugins.size())
        message += "Plugin-Information: \n";
    else
        message += "No plugins have been added to paserd.conf";
    for (unsigned int i = 0; i < conf.plugins.size(); i++) {
        message.append(5, ' ');
        message += conf.plugins.at(i).name;
        message += "\n\n";
    }
    message += "\n\n";

    tmp_log->PASER_log(1, message.c_str());
}

