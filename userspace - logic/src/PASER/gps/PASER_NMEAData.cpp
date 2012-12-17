/**
 *\class        PASER_NMEAData
 *@brief        Class implements a GPS Data
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

#include <string.h>
//#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "PASER_NMEAData.h"
#include <iostream>

using namespace std;

PASER_NMEAData::PASER_NMEAData() {

}

string PASER_NMEAData::getTimeOfFix() {
    //return GPGGA.getTimeOfFix();
    return GPRMC.getTimeOfFix();
}

string PASER_NMEAData::getDateOfFix() {
    return GPRMC.getDateOfFix();
}

string PASER_NMEAData::getLatitude() {
    return GPGGA.getLatitude();
}

double PASER_NMEAData::getLatitude_double() {
    return GPGGA.getLatitude_double();
}

string PASER_NMEAData::getLongitude() {
    return GPGGA.getLongitude();
}

double PASER_NMEAData::getLongitude_double() {
    return GPGGA.getLongitude_double();
}

string PASER_NMEAData::getAltitude() {
    return GPGGA.getAltitude();
}

double PASER_NMEAData::getAltitude_double() {
    return GPGGA.getAltitude_double();
}

/* NMEA_GPGGA */
void PASER_NMEA_GPG::setTimeOfFix(string timeOfFix) {
    this->timeOfFix = timeOfFix;
}

string PASER_NMEA_GPG::getTimeOfFix() {
    //074628.000
    if (timeOfFix.length() > 6) {
        string temp = timeOfFix;
        temp = temp.substr(0, 2) + ":" + temp.substr(2, 2) + ":" + temp.substr(4, 2);
        return temp;
    } else {
        return timeOfFix;
    }
}

void PASER_NMEA_GPG::setLatitude(string latitude) {
    this->latitude = latitude;
}

string PASER_NMEA_GPG::getLatitude() {
    return latitude;
}

double PASER_NMEA_GPG::getLatitude_double() {
    //5129.5090,N
    if (strcmp(latitude.c_str(), "NA,NA") == 0 || latitude.size() == 0) {
        return 0.0;
    } else {
        return convertPosStringToPosDouble(latitude);
    }
}

void PASER_NMEA_GPG::setLongitude(string longitude) {
    this->longitude = longitude;
}

string PASER_NMEA_GPG::getLongitude() {
    return longitude;
}

double PASER_NMEA_GPG::getLongitude_double() {
    //5129.5090,N
    if (strcmp(longitude.c_str(), "NA,NA") == 0 || longitude.size() == 0) {
        return 0.0;
    } else {
        return convertPosStringToPosDouble(longitude);
    }
}

void PASER_NMEA_GPG::setFixQuality(int fixQuality) {
    this->fixQuality = fixQuality;
}

int PASER_NMEA_GPG::getFixQuality() {
    return this->fixQuality;
}

void PASER_NMEA_GPG::setNumberOfSats(int numSatellites) {
    this->numSatellites = numSatellites;
}

int PASER_NMEA_GPG::getNumberOfSats() {
    return this->numSatellites;
}

void PASER_NMEA_GPG::setHorDilution(double horDilution) {
    this->horizontalDilution = horDilution;
}

double PASER_NMEA_GPG::getHorDilution() {
    return this->horizontalDilution;
}

void PASER_NMEA_GPG::setAltitude(string altitude) {
    this->altitude = altitude;
}

string PASER_NMEA_GPG::getAltitude() {
    return this->altitude;
}

double PASER_NMEA_GPG::getAltitude_double() {
    string altitude = this->altitude;
    if (strcmp(altitude.c_str(), "NA,M") == 0 || altitude.size() == 0) {
        return 0.0;
    } else {
        return atof((altitude.substr(0, altitude.find_first_of(','))).c_str());
    }
}

void PASER_NMEA_GPG::setHeightGeoid(string heightGeoid) {
    this->heightGeoid = heightGeoid;
}

string PASER_NMEA_GPG::getHeightGeoid() {
    return this->heightGeoid;
}

double PASER_NMEA_GPG::getHeightGeoid_double() {
    string heightGeoid = this->heightGeoid;
    if (strcmp(heightGeoid.c_str(), "NA,M") == 0 || heightGeoid.size() == 0) {
        return 0.0;
    } else {
        return atof((heightGeoid.substr(0, heightGeoid.find_first_of(','))).c_str());
    }
}

double PASER_NMEA_GPG::convertPosStringToPosDouble(string PosString) {
    //5129.5090,N
    double degree = atof((PosString.substr(0, PosString.find_first_of('.') - 2)).c_str());
    double position_dec = atof((PosString.substr(PosString.find_first_of('.') - 2, PosString.find_first_of(','))).c_str()) / 60.0;
    double position = degree + position_dec;
    if (strcmp(PosString.substr(PosString.find_first_of(',') + 1, 1).c_str(), "N") == 0) {
        //orientation N o E
    } else if (strcmp(PosString.substr(PosString.find_first_of(',') + 1, 1).c_str(), "S") == 0
            || strcmp(PosString.substr(PosString.find_first_of(',') + 1, 1).c_str(), "W") == 0) {
        //orientation S or W
        position = position * -1;
    } else {	//Error sparsing string
                //cout << "Error parsing position information" << endl;
    }
    return position;
}

/* NMEA_GPRMC */
void PASER_NMEA_GPRMC::setTimeOfFix(string timeOfFix) {
    this->timeOfFix = timeOfFix;
}

string PASER_NMEA_GPRMC::getTimeOfFix() {
    //074628.000
    if (timeOfFix.length() > 6) {
        string temp = timeOfFix;
        temp = temp.substr(0, 2) + ":" + temp.substr(2, 2) + ":" + temp.substr(4, 2);
        return temp;
    } else {
        return timeOfFix;
    }
}

void PASER_NMEA_GPRMC::setActive(string active) {
    if (strcmp(active.c_str(), "A") == 0) {
        this->active = true;
    } else {
        this->active = false;
    }
}

bool PASER_NMEA_GPRMC::getActive() {
    return this->active;
}

void PASER_NMEA_GPRMC::setLatitude(string latitude) {
    this->latitude = latitude;
}

string PASER_NMEA_GPRMC::getLatitude() {
    return latitude;
}

double PASER_NMEA_GPRMC::getLatitude_double() {
    //5129.5090,N
    if (strcmp(latitude.c_str(), "NA,NA") == 0 || latitude.size() == 0) {
        return 0.0;
    } else {
        return convertPosStringToPosDouble(latitude);
    }
}

void PASER_NMEA_GPRMC::setLongitude(string longitude) {
    this->longitude = longitude;
}

string PASER_NMEA_GPRMC::getLongitude() {
    return longitude;
}

double PASER_NMEA_GPRMC::getLongitude_double() {
    //5129.5090,N
    if (strcmp(longitude.c_str(), "NA,NA") == 0 || longitude.size() == 0) {
        return 0.0;
    } else {
        return convertPosStringToPosDouble(longitude);
    }
}

void PASER_NMEA_GPRMC::setSpeed(double speed) {
    this->speed = speed;
}

double PASER_NMEA_GPRMC::getSpeed() {
    return this->speed;
}

void PASER_NMEA_GPRMC::setTrackingAngle(double trackingAngle) {
    this->tracking_angle = trackingAngle;
}

double PASER_NMEA_GPRMC::getTrackingAngle() {
    return this->tracking_angle;
}

void PASER_NMEA_GPRMC::setDateOfFix(string dateOfFix) {
    //std::cout << "setting Date: " << timeOfD
    this->dateOfFix = dateOfFix;
}

string PASER_NMEA_GPRMC::getDateOfFix() {
    //074628.000
    if (dateOfFix.length() > 5) {
        string temp = dateOfFix;
        temp = temp.substr(0, 2) + "." + temp.substr(2, 2) + "." + temp.substr(4, 2);
        return temp;
    } else {
        return dateOfFix;
    }
}

void PASER_NMEA_GPRMC::setMagneticVariation(string magnetic_variation) {
    this->magnetic_variation = magnetic_variation;
}

string PASER_NMEA_GPRMC::getMagneticVariation() {
    return magnetic_variation;
}

double PASER_NMEA_GPRMC::getMagneticVariation_double() {
    //5129.5090,N
    if (strcmp(magnetic_variation.c_str(), "NA,NA") == 0 || magnetic_variation.size() == 0) {
        return 0.0;
    } else {
        return convertPosStringToPosDouble(magnetic_variation);
    }
}

void PASER_NMEA_GPRMC::setTypeOfFix(char typeOfFix) {
    this->typeOfFix = typeOfFix;
}

char PASER_NMEA_GPRMC::getTypeOfFix() {
    return this->typeOfFix;
}

double PASER_NMEA_GPRMC::convertPosStringToPosDouble(string PosString) {
    //5129.5090,N
    double degree = atof((PosString.substr(0, PosString.find_first_of('.') - 2)).c_str());
    double position_dec = atof((PosString.substr(PosString.find_first_of('.') - 2, PosString.find_first_of(','))).c_str()) / 60.0;
    double position = degree + position_dec;
    if (strcmp(PosString.substr(PosString.find_first_of(',') + 1, 1).c_str(), "N") == 0) {
        //orientation N o E
    } else if (strcmp(PosString.substr(PosString.find_first_of(',') + 1, 1).c_str(), "S") == 0
            || strcmp(PosString.substr(PosString.find_first_of(',') + 1, 1).c_str(), "W") == 0) {
        //orientation S or W
        position = position * -1;
    } else {	//Error sparsing string
                //cout << "Error parsing position information" << endl;
    }
    return position;
}

/* NMEA_GODDE */
double PASER_NMEA_GODDE::getAltitude_double() {
    /*
     string altitude = this->altitude;
     if (strcmp(altitude.c_str(), "NA,M")==0 || altitude.size() == 0){
     return 0.0;
     }else{
     return atof((altitude.substr(0,altitude.find_first_of(','))).c_str());
     }*/
    return this->altitude;
}

void PASER_NMEA_GODDE::setReference(int ref) {
    //ref in Pa
    //convert to absolute altitude;
    this->reference = ref;
}

int PASER_NMEA_GODDE::getReference() {
    return this->reference;
}

void PASER_NMEA_GODDE::setCurrentValue(int cValue) {
    //cValue in Pa -> Convert to absolute altitude in m
    this->currentValue = cValue;
    if (this->initValue == 0) {
        this->initValue = cValue;
    }
    this->altitude = heightFormula(cValue);
    this->altitude_rel = heightFormula(cValue) - heightFormula(this->initValue);
}

int PASER_NMEA_GODDE::getCurrentValue() {
    return this->currentValue;
}

void PASER_NMEA_GODDE::setTemperature(double temp) {

    this->temperature = temp;
//	std::cout << "Temp: " << temp << " C" << std::endl;
}

double PASER_NMEA_GODDE::getTemperature() {
    return this->temperature;
}

double PASER_NMEA_GODDE::getRelAltitude() {
//	double ref_height = heightFormula(this->initValue);
//	double curr_height = heightFormula(this->currentValue);
    //std::cout << "curr_height: " << curr_height << " ref_height: " << ref_height << std::endl;
    return this->altitude_rel;
}

double PASER_NMEA_GODDE::heightFormula(int pressure) {
    //implementation of height formula
    double tmppressure = pressure / 100.0; //convert from Pa to hPa
    double pressure_at_sea = 1013.25;
    return -288.0 * ((pow((tmppressure / pressure_at_sea), 0.190294957) - 1) / 0.00651);
}

