********** COMPILE **********


To compile PASER Daemon you need to install the following packages:

openssl, libssl, libssl-dev,
libnl-3-200, libnl-genl-3-200, libnl-route-3-200, libnl-nf-3-200, libnl-cli-3-200, libnl-3-dev, 
libnl-genl-3-dev, libnl-route-3-dev, libnl-nf-3-dev, libnl-cli-3-dev,
libconfig9 libconfig9-dev libconfig++9 libconfig++9-dev,
libboost-all-dev



To compile PASER switch into the "Debug" or "Release" directory and type "make".




********** HOW TO CONFIGURE **********


Copy the "cert" directory and the "paserd.conf" file to /etc/PASER/.
 Use the /etc/PASER/paserd.conf to configure PASER.

Note that 
one of the nodes running PASER must be set as a gateway node. This node must be able to 
communicate with KDC (for example over Ethernet). Thus, the gateway must be aware of the IP-Address of the KDC, which you can edit in the paserd.conf file. 

In the option block "Interfaces" you must input the name and the IP Address of the interfaces on which PASER should run 

Interfaces:

{
  
<NAME_OF_THE_INTERFACE>
:  
{
    
IPv4_addr = <IP_ADDRESS_OH_THE_INTERFACE>
  
} 

}
. 

If the node has a GPS receiver and the GPS information can be read on a serial port in NMEA format, 
you should set the attributes GPS_ENABLE to "1", GPS_SERIAL_PORT to "PATH_TO_SERIAL_PORT"
and GPS_SERIAL_SPEED to "READ_SPEED". If the node does not have a GPS receiver, you must set GPS_ENABLE to "0". In that case, assign 
GPS_STATIC_LAT and GPS_STATIC_LON with the static GPS coordinates of the node. 




********** RUN **********

To run PASER, you should first run KDC and at least one node must be set as a gateway.


To run KDC switch into the "Debug" or "Release" directory and type:=
 sudo ./PASER -r KDC


To run PASER you first need to run ROM and then to start the PASER daemon.

Switch into the ROM directory. 
Compile ROM with "make".
Start ROM:=
 "insmod rom.ko"
 or
 "insmod rom.ko isGateway=1" in case the node is a gateway.


Switch into the "Debug" or "Release" directory. 
Start the PASER Daemon:=
 sudo ./PASER




********** Enabling Link Layer Feedback for Mobile Scenarios ***********
To enable the Link Layer Feedback module of PASER your wireless card must be using the ath9k driver. 
You have to patch you driver using the LLF_ath9k.patch provided in the rom directory.
Afterwards you just have to run rom using the following command: "insmod rom.ko enableLLF=1". 
You might use the "LLFPerSecond" option to define number of required LLFs in one second in order to consider a route broken. E.g., "insmod rom.ko enableLLF=1 LLFPerSecond=5". The default value of this option is 1. 


********** STOP KDC and PASER **********


Stop KDC Daemon:= sudo kill `cat /tmp/kdcd.lock`

Stop PASER Daemon := sudo kill `cat /tmp/paserd.lock` && rmmod rom.ko