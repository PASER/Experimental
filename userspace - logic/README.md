Copyright: (C) 2012 Communication Networks Institute (CNI - Prof. Dr.-Ing. Christian Wietfeld) at Technische Universitaet Dortmund, Germany: http://www.kn.e-technik.tu-dortmund.de/.

This implementation is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

Authors: Eugen.Paul and Mohamad.Sbeiti.

Installation

PASER daemon and key distribution center (KDC): To install the PASER daemon and the KDC, the following packages are required:
openssl, libssl, libssl-dev, libnl-3-200, libnl-genl-3-200, libnl-route-3-200, libnl-nf-3-200, libnl-cli-3-200, libnl-3-dev, libnl-genl-3-dev, libnl-route-3-dev, libnl-nf-3-dev, libnl-cli-3-dev, libconfig9 libconfig9-dev libconfig++9 libconfig++9-dev, libboost-all-dev.
After installing these packages, move to the Debug or Release directory found in the userspace - logic directory and run make.

Kernel module (ROUTE-O-MATIC): Move to the kernel module - rom directory and run make. 

Configuration

PASER daemon: Copy the cert directory and the paserd.conf file from the userspace - logic  to /etc/PASER/. Use /etc/PASER/paserd.conf to configure PASER. Set in the options block Interfaces the name and the IP Address of the interfaces on which PASER should run. If the node has a GPS receiver and the GPS information can be read via a serial port in NMEA format,  set the attributes GPS_ENABLE to "1", GPS_SERIAL_PORT to "PATH_TO_SERIAL_PORT" and GPS_SERIAL_SPEED to "READ_SPEED", respectively. In case the node does not have a GPS receiver, set GPS_ENABLE to "0" and assign manually GPS_STATIC_LAT and GPS_STATIC_LON with the static GPS coordinates of the node.

Note that one of the nodes running PASER must be set as a gateway node. This node must be able to communicate with the key distribution center (KDC) e.g., over Ethernet. Thus, this gateway node must be aware of the IP-Address of the KDC. The latter must be set in the paserd.conf file.

Enabling Link Layer Feedback for mobile scenarios: To enable the Link Layer Feedback module of PASER, your wireless card must be using the ath9k driver. You have to patch you driver using the LLF_ath9k.patch provided in the kernel module - rom directory.

Kernel module - ROUTE-O-MATIC (ROM):  The kernel module supports currently three configuration parameters that might be set when inserting the module: isGateway,  enableLLF and LLFPerSecond. isGateway ist set to 1 if the node is a gateway, its default value is 0.  enableLLF is set to 1 if Link Layer Feedback should be activated, its default value is 0.  The LLFPerSecond option is used in combination with the enableLLF option. It defines the number of required LLFs in one second in order to consider a route broken. The default value of this option is 1.

Run

Before running PASER, one node must be set as gateway (see the configuration part) and the KDC must be started on the gateway node or on a secure remote machine connected with the gateway node via a secure channel. Below are the commands to run KDC and PASER:
KDC:  <PATH>/PASER/Release/PASER -r KDC
Kernel module - ROM: insmod <PATH>/kmod/rom.ko isGateway=<0|1> enable_llf_support=<0|1> <LLFPerSecond=<3>>
PASER daemon: <PATH>/PASER/Release/PASER

 
Terminate
KDC: kill $(cat /tmp/kdcd.lock)
Kernel module ROM: rmmod rom.ko
PASER daemon: kill $(cat /tmp/paserd.lock)

A thorough documentation of this code is provided on: www.paser.info.