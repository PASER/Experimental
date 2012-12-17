/**
 *\class        PASER_NMEA_Parser
 *@brief        Class provides functions for parsing a GPS Data
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

//#include <string>
#include "string.h"
#include <stdlib.h>
#include "PASER_NMEAParser.h"
//#include "settings.h"


// Construction/Destruction
PASER_NMEA_Parser::PASER_NMEA_Parser() {
    GPSMap["GPGGA"] = NMEA_GPGGA;
    GPSMap["GPGSA"] = NMEA_GPGSA;
    GPSMap["GPGSV"] = NMEA_GPGSV;
    GPSMap["GPRMB"] = NMEA_GPRMB;
    GPSMap["GPRMC"] = NMEA_GPRMC;
    GPSMap["GPGLL"] = NMEA_GPGLL;
    GPSMap["GPVTG"] = NMEA_GPVTG;
    GPSMap["GPZDA"] = NMEA_GPZDA;
    GPSMap["GODDE"] = GODDE;

    //m_logging = FALSE;
}

void PASER_NMEA_Parser::ParseNMEASentence(string &sentence, PASER_NMEAData *myNMEAData) {
    string address = "test";

    if (strcmp(sentence.substr(0, 1).c_str(), "$") == 0 && sentence.find_last_of("$") < 1 && sentence.length() > 6) //&& strcmp (sentence.substr(sentence.length()-5,1).c_str(),"*") == 0)
            {
        address = sentence.substr(1, 5);

        switch (GPSMap[address]) {
        case NMEA_GPGGA:
            ProcessGPGGA(sentence, myNMEAData);
            break;
        case NMEA_GPGSA:
            ProcessGPGSA(sentence, myNMEAData);
            break;
        case NMEA_GPGSV:
            ProcessGPGSV(sentence, myNMEAData);
            break;
        case NMEA_GPRMB:
            ProcessGPRMB(sentence, myNMEAData);
            break;
        case NMEA_GPRMC:
            ProcessGPRMC(sentence, myNMEAData);
            break;
        case NMEA_GPGLL:
            ProcessGPGLL(sentence, myNMEAData);
            break;
        case NMEA_GPVTG:
            ProcessGPVTG(sentence, myNMEAData);
            break;
        case NMEA_GPZDA:
            ProcessGPZDA(sentence, myNMEAData);
            break;
        case GODDE:
            ProcessGODDE(sentence, myNMEAData);
            break;
        default:
            if (reportlevel > 0) {
                cout << "!!!!!!!!!!!!!!received unknown sentence !!!!!!!!!!!!!!!!" << address << endl;
            }
            break;
        }

        i++;
        myNMEAData->update = i;
    } else {
        if (reportlevel > 0) {
            cout << "Error parsing: " << sentence << endl;
        }
    }
}

void PASER_NMEA_Parser::SplitSentence(string &sentence, vector<string> &result) {
    int cutAt;
    while ((cutAt = sentence.find_first_of(',')) != sentence.npos) {
        if (cutAt > 0) {
            result.push_back(sentence.substr(0, cutAt));
        } else {
            result.push_back("NA");
        }
        sentence = sentence.substr(cutAt + 1);
    }
    if (sentence.length() > 0) {
        result.push_back(sentence);
    }
}

/*
 GPGGA Sentence format
 $GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M, ,*47
 |      |      |          |           | |  |   |       |      |  |
 |      |      |          |           | |  |   |       |      | checksum data
 |      |      |          |           | |  |   |       |      |
 |      |      |          |           | |  |   |       |      empty field
 |      |      |          |           | |  |   |       |
 |      |      |          |           | |  |   |       46.9,M Height of geoid (m) above WGS84 ellipsoid
 |      |      |          |           | |  |   |
 |      |      |          |           | |  |   545.4,M Altitude (m) above mean sea level
 |      |      |          |           | |  |
 |      |      |          |           | |  0.9 Horizontal dilution of position (HDOP)
 |      |      |          |           | |
 |      |      |          |           | 08 Number of satellites being tracked
 |      |      |          |           |
 |      |      |          |           1 Fix quality:0 = invalid
 |      |      |          |              1 = GPS fix (SPS)
 |      |      |          |              2 = DGPS fix
 |      |      |          |              3 = PPS fix
 |      |      |          |              4 = Real Time Kinematic
 |      |      |          |              5 = Float RTK
 |      |      |          |              6 = estimated (dead reckoning) (2.3 feature)
 |      |      |          |              7 = Manual input mode
 |      |      |          |              8 = Simulation mode
 |      |      |          |
 |      |      |          01131.000,E Longitude 11 deg 31.000' E
 |      |      |
 |      |      4807.038,N Latitude 48 deg 07.038' N
 |      |
 |      123519 Fix taken at 12:35:19 UTC
 |
 GGA Global Positioning System Fix Data

 0. Sentence
 1. FixTaken
 2. latitude
 3. N/S
 4. longitude
 5. E/W
 6. Fix Quality
 7. # Satellites
 8. Horizontal dilution
 9. Altitude
 10. Altitude unit
 11. Height of geoid
 12. Height of geoid unit
 13. emty field
 14. checksum data
 */
void PASER_NMEA_Parser::ProcessGPGGA(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPGGA: " << sentence << endl;
    }

    vector<string> *v = new vector<string>();
    SplitSentence(sentence, *v);

    if (v->size() > 14) {
        try {
            myNMEAData->GPGGA.setTimeOfFix(v->at(1));
            myNMEAData->GPGGA.setLatitude(v->at(2) + "," + v->at(3));
            myNMEAData->GPGGA.setLongitude(v->at(4) + "," + v->at(5));
            myNMEAData->GPGGA.setFixQuality(atoi(v->at(6).c_str()));
            myNMEAData->GPGGA.setNumberOfSats(atoi(v->at(7).c_str()));
            myNMEAData->GPGGA.setHorDilution(atof(v->at(8).c_str()));
            myNMEAData->GPGGA.setAltitude(v->at(9) + "," + v->at(10));
            myNMEAData->GPGGA.setHeightGeoid(v->at(11) + "," + v->at(12));
        } catch (...) {
            if (reportlevel > 3) {
                cout << "Error Parsing GPGGA - Exeception:" << endl;
            }
        }
    } else {
        if (reportlevel > 2) {
            cout << "Error Parsing GPGGA - Not enough fields" << endl;
        }
    }

}

void PASER_NMEA_Parser::ProcessGPGSA(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPGSA: not implemented" << endl;
    }
}

void PASER_NMEA_Parser::ProcessGPGSV(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPGSV: not implemented" << endl;
    }
}

void PASER_NMEA_Parser::ProcessGPRMB(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPRMB: not implemented" << endl;
    }
}

/*
 $GPRMC,113653.000,A,5129.5242,N,00724.6873,E,2.39,120.07,050710,,*0A
 $GPRMC,191410,A,4735.5634,N,00739.3538,E,0.0, 0.0,181102,0.4,E,A*19
 ^      ^ ^           ^            ^   ^   ^      ^     ^
 |      | |           |            |   |   |      |     |
 |      | |           |            |   |   |      |     Neu in NMEA 2.3:
 |      | |           |            |   |   |      |     Art der Bestimmung
 |      | |           |            |   |   |      |     A=autonomous (selbst)
 |      | |           |            |   |   |      |     D=differential
 |      | |           |            |   |   |      |     E=estimated (geschätzt)
 |      | |           |            |   |   |      |     N=not valid (ungültig)
 |      | |           |            |   |   |      |     S=simulator
 |      | |           |            |   |   |      |
 |      | |           |            |   |   |      Missweisung (mit Richtung)
 |      | |           |            |   |   |
 |      | |           |            |   |   Datum: 18.11.2002
 |      | |           |            |   |
 |      | |           |            |   Bewegungsrichtung in Grad (wahr)
 |      | |           |            |
 |      | |           |            Geschwindigkeit über Grund (Knoten)
 |      | |           |
 |      | |           Längengrad mit (Vorzeichen)-Richtung (E=Ost, W=West)
 |      | |           007° 39.3538' Ost
 |      | |
 |      | Breitengrad mit (Vorzeichen)-Richtung (N=Nord, S=Süd)
 |      | 46° 35.5634' Nord
 |      |
 |      Status der Bestimmung: A=Active (gültig); V=void (ungültig)
 |
 Uhrzeit der Bestimmung: 19:14:10 (UTC-Zeit)

 0. Sentence
 1. Fix taken
 2. Status
 3. Latitude
 4. N/S
 5. Longitude
 6. E/W 
 7. speed
 8. heading
 9. Date of Fix
 10. Magnetic Variation
 11. Magnetic Variation E/W
 12. Type of fix
 */

void PASER_NMEA_Parser::ProcessGPRMC(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPRMC: " << sentence << endl;
    }
    vector<string> *v = new vector<string>();
    SplitSentence(sentence, *v);

    if (v->size() > 11) {
        try {
            myNMEAData->GPRMC.setTimeOfFix(v->at(1));
            myNMEAData->GPRMC.setActive(v->at(2));
            myNMEAData->GPRMC.setLatitude(v->at(3) + "," + v->at(4));
            myNMEAData->GPRMC.setLongitude(v->at(5) + "," + v->at(6));
            myNMEAData->GPRMC.setSpeed(atof(v->at(7).c_str()));
            myNMEAData->GPRMC.setTrackingAngle(atof(v->at(8).c_str()));
            myNMEAData->GPRMC.setDateOfFix(v->at(9));
            myNMEAData->GPRMC.setMagneticVariation(v->at(10) + "," + v->at(11));
            if (v->size() == 13) {
                myNMEAData->GPRMC.setTypeOfFix(v->at(12)[0]);
            } else {
                myNMEAData->GPRMC.setTypeOfFix('-');
            }
        } catch (...) {
            if (reportlevel > 3) {
                cout << "Error Parsing GPRMC - Exception" << endl;
            }
        }
    } else {
        if (reportlevel > 2) {
            cout << "Error Parsing GPRMC - Not enough fields" << endl;
        }
    }

}

void PASER_NMEA_Parser::ProcessGPZDA(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPZDA: not implemented" << endl;
    }
}

void PASER_NMEA_Parser::ProcessGPGLL(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPGLL: not implemented" << endl;
    }
}

void PASER_NMEA_Parser::ProcessGPVTG(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GPVTG: not implemented" << endl;
    }
}

/*
 $GODDE,219.99,M,408,217,*45
 |       |  |  |   |
 |       |  |  |   referenze
 |       |  |  current value
 |       |  alitutde unit
 |       |
 |       altitude
 |
 Godde sentence
 */

/*
 $GODDE,100583,Pa,16384,Pa,-18663,Pa,243,C,*15
 |     |    |    |   |    |    |  |  |
 |     |    |    |   |    |    |  |  |
 |     |    |    |   |    |    |  |  unit Temperature
 |     |    |    |   |    |    |  current Temperature
 |     |    |    |   |    |    unit pressure difference
 |     |    |    |   |    pressure difference
 |     |    |    |   ref pressure unit
 |     |    |    ref pressure
 |     |    current pressure unit
 |     current pressure
 Godde sentence

 0. Godde sentence
 1. current pressure
 2. unit
 3. ref pressure
 4. unit
 5. pressure diff
 6. unit
 7. temperature (243 = 24.3 C)
 8. temp unit

 */
void PASER_NMEA_Parser::ProcessGODDE(string &sentence, PASER_NMEAData *myNMEAData) {
    if (reportlevel > 2) {
        cout << "Parsing GODDE: " << sentence << endl;
    }

    vector<string> *v = new vector<string>();
    SplitSentence(sentence, *v);

    //myNMEAData->GODDE.setAltitude(v->at(1) + "," + v->at(2));
    myNMEAData->GODDE.setCurrentValue(atoi(v->at(1).c_str()));
    myNMEAData->GODDE.setReference(atoi(v->at(3).c_str()));
    myNMEAData->GODDE.setTemperature(atoi(v->at(7).c_str()) / 10.0);

}

void PASER_NMEA_Parser::Test() {
    if (reportlevel > 0) {
        printf("Getting ready\r\r");
    }
}

PASER_NMEA_Parser::~PASER_NMEA_Parser() {
    //if(m_logging)
    //  m_outputFile.Close();
}
