/**
 *\class        GPSDATA::PASER_GPS
 *@brief        Class provides API to read GPS Data
 *
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

#include "PASER_gpsReader.h"
#include "../config/PASER_defs.h"

GPSDATA::PASER_GPS::PASER_GPS(PASER_global* paser_global){
    pGlobal = paser_global;
    if(conf.GPS_ENABLE == 1){
        lat = 0;
        lon = 0;
        alt = 0;

        gpsPasrer = new PASER_NMEA_Parser();
        gpsData = new PASER_NMEAData();
    }else{
        lat = conf.GPS_STATIC_LAT;
        lon = conf.GPS_STATIC_LON;
        alt = conf.GPS_STATIC_ALT;
    }
}

double GPSDATA::PASER_GPS::getLatitude() {
    return lat;
}

double GPSDATA::PASER_GPS::getLongitude() {
    return lon;
}

double GPSDATA::PASER_GPS::getAltitude() {
    return alt;
}

void GPSDATA::PASER_GPS::Handler(const boost::system::error_code& error, size_t bytes_transferred) {
    CurrentData = std::string(boost::asio::buffer_cast<const char*>(b.data()), b.size());
    size_t Index = CurrentData.find_first_of('\n');
    std::string _rLine;
    if (Index != string::npos) {
        _rLine = CurrentData.substr(0, Index);
        //Do stuff with header, maybe construct a std::string with std::string(header,header+length)
        b.consume(Index + 1);
    } else {
        _rLine = CurrentData;
    }
    gpsPasrer->ParseNMEASentence(_rLine, gpsData);
//        gpsMutex.lock();
    if (gpsData->getLatitude_double() != 0.0) {
        lat = gpsData->getLatitude_double();
    }
    if (gpsData->getLongitude_double() != 0.0) {
        lon = gpsData->getLongitude_double();
    }
    if (gpsData->getAltitude_double() != 0.0) {
        alt = gpsData->getAltitude_double();
    }
//        gpsMutex.unlock();

    boost::asio::async_read_until(*m_Port, b, '\n',
            boost::bind(&GPSDATA::PASER_GPS::Handler, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void GPSDATA::PASER_GPS::startGPS() {
    if(conf.GPS_ENABLE == 0){
        return;
    }
    bool error;
    bool m_ReadingStarted = false;
    // repeating reconnection if problems arise
    do {
        error = false;
        try {
            // create the serial device, note it takes the io service and the port name
            m_Port = new serial_port(m_IO, conf.GPS_SERIAL_PORT);
//            m_Port = new serial_port(m_IO, "/dev/ttyS2");
        } catch (...) {
            error = true;
            PASER_LOG_WRITE_LOG(PASER_LOG_ERROR, "Problem wile trying to access port %s\n", conf.GPS_SERIAL_PORT.c_str());
            boost::xtime xt;
            boost::xtime_get(&xt, boost::TIME_UTC);

            xt.nsec += 1000000000;
            boost::thread::sleep(xt);
            // after some time try to reconnect;
        }
    } while (error);

    // prepare settings
    serial_port_base::baud_rate BAUD(conf.GPS_SERIAL_SPEED); // what baud rate do we communicate at
//    serial_port_base::baud_rate BAUD(4800); // what baud rate do we communicate at
    serial_port_base::character_size CSIZE2(8); // how big is each "packet" of data (default is 8 bits)
    serial_port_base::flow_control FLOW(serial_port_base::flow_control::none); // what flow control is used (default is none)
    serial_port_base::parity PARITY(serial_port_base::parity::none); // what parity is used (default is none)
    serial_port_base::stop_bits STOP(serial_port_base::stop_bits::one); // how many stop bits are used (default is one)

    // go through and set all the options as we need them
    // all of them are listed, but the default values work for most cases
    m_Port->set_option(BAUD);
    m_Port->set_option(CSIZE2);
    m_Port->set_option(FLOW);
    m_Port->set_option(PARITY);
    m_Port->set_option(STOP);

    if (!m_ReadingStarted) {
        boost::thread t(boost::bind(&boost::asio::io_service::run, &m_IO));
        boost::asio::async_read_until(*m_Port, b, '\n',
                boost::bind(&GPSDATA::PASER_GPS::Handler, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
        m_ReadingStarted = true;
    }

}
