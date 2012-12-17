/**
 *\class        PASER_NMEAData
 *@brief        Class implements a GPS Data
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

#ifndef PASER_NMEA_GPG_H_
#define PASER_NMEA_GPG_H_

#include <string>
#include <math.h>
using namespace ::std;

class PASER_NMEA_GPG {
private:
    string timeOfFix;
    string latitude;
    double latitude_double;
    string longitude;
    double longitude_double;
    int fixQuality;
    int numSatellites;
    double horizontalDilution;
    string altitude;
    string heightGeoid;
    double convertPosStringToPosDouble(string PosString);

public:
    void setTimeOfFix(string timeOfFix);
    string getTimeOfFix();

    void setLatitude(string latitude);
    string getLatitude();
    double getLatitude_double();

    void setLongitude(string longitude);
    string getLongitude();
    double getLongitude_double();

    void setFixQuality(int fixQuality);
    int getFixQuality();

    void setNumberOfSats(int numSatellites);
    int getNumberOfSats();

    void setHorDilution(double horDilution);
    double getHorDilution();

    void setAltitude(string altitude);
    string getAltitude();
    double getAltitude_double();

    void setHeightGeoid(string heightGeoid);
    string getHeightGeoid();
    double getHeightGeoid_double();
};

class PASER_NMEA_GPRMC {
private:
    string timeOfFix;
    bool active;
    string latitude;
    double latitude_double;
    string longitude;
    double longitude_double;
    double speed;
    double tracking_angle;
    string dateOfFix;
    string magnetic_variation;
    double magnetic_variation_double;
    char typeOfFix;

public:
    void setTimeOfFix(string timeOfFix);
    string getTimeOfFix();

    void setActive(string active);
    bool getActive();

    void setLatitude(string latitude);
    string getLatitude();
    double getLatitude_double();

    void setLongitude(string longitude);
    string getLongitude();
    double getLongitude_double();

    void setSpeed(double speed);
    double getSpeed();

    void setTrackingAngle(double trackingAngle);
    double getTrackingAngle();

    void setDateOfFix(string dateOfFix);
    string getDateOfFix();

    void setMagneticVariation(string MagneticVariation);
    string getMagneticVariation();
    double getMagneticVariation_double();

    void setTypeOfFix(char typeOfFix);
    char getTypeOfFix();

    double convertPosStringToPosDouble(string PosString);
};

class PASER_NMEA_GODDE {
private:
    double altitude;
    double altitude_rel;

    int reference;
    int initValue;
    int currentValue;
    double temperature;
    double heightFormula(int pressure);

public:
    double getAltitude_double();
    double getRelAltitude();

    void setReference(int ref);
    int getReference();

    void setCurrentValue(int cValue);
    int getCurrentValue();

    void setTemperature(double temperature);
    double getTemperature();

};

class PASER_NMEAData {
private:
    //double convertPosStringToPosDouble(string PosString);

public:
    PASER_NMEAData();
    int update;

    PASER_NMEA_GODDE GODDE;
    PASER_NMEA_GPG GPGGA;
    PASER_NMEA_GPRMC GPRMC;

    string getTimeOfFix();
    string getDateOfFix();

    string getLatitude();
    double getLatitude_double();

    string getLongitude();
    double getLongitude_double();

    string getAltitude();
    double getAltitude_double();
};

#endif /*PASER_NMEA_GPG_H_*/
