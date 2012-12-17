namespace GPSDATA {
/**
 *\namespace    GPSDATA
 *\class        PASER_GPS
 *@brief        Class provides API to read GPS Data
 *@ingroup      GPS
 *\authors      Eugen.Paul | Mohamad.Sbeiti \@paser.info
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
class PASER_GPS;
}

#ifndef GPSDATA_H_
#define GPSDATA_H_

#include <iostream>
#include "net/if.h"
#include "boost/asio/io_service.hpp"
#include "boost/asio/write.hpp"
#include "boost/asio/read.hpp"
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>

#include "PASER_NMEAParser.h"

#include "../config/PASER_global.h"

using namespace std;
using namespace boost::asio;

namespace GPSDATA {
class PASER_GPS {
private:
    PASER_global* pGlobal;

    boost::asio::streambuf b;
    boost::asio::serial_port *m_Port;
    boost::asio::io_service m_IO;

    boost::mutex gpsMutex;

    std::string CurrentData;
    PASER_NMEAData* gpsData;
    PASER_NMEA_Parser* gpsPasrer;

    double lat;
    double lon;
    double alt;

public:

    /**
     * Constructor of GPS Object.
     *
     *@param paser_global Pointer to global object
     *
     *@return nada
     */
    PASER_GPS(PASER_global* paser_global);

    /**
     * Get Latitude of the Node
     * @return Latitude of the Node
     */
    double getLatitude();
    /**
     * Get Longitude of the Node
     * @return Longitude of the Node
     */
    double getLongitude();
    /**
     * Get Altitude of the Node
     * @return Altitude of the Node
     */
    double getAltitude();

    /**
     * Callback function to read GPS data from serial port.
     * @return nada
     */
    void Handler(const boost::system::error_code& error, size_t bytes_transferred);

    /**
     * Main function to initialize GPS Data and start read GPS Data from serial port.
     * This Function must be called once at initialization of PASER.
     * @return nada
     */
    void startGPS();
};
}
;

#endif
