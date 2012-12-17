/**
 *\class        PASER_NMEA_Parser
 *@brief        Class provides functions for parsing a GPS Data
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

#ifndef NMEAParser_H_
#define NMEAParser_H_

#include <string>
#include <iostream>
#include <stdio.h>
#include <map>
#include <vector>
//#include "cGPSData.h"

#include "PASER_NMEAData.h"


using namespace::std;

class PASER_NMEA_Parser
{
public:
	PASER_NMEA_Parser();
	//NMEAParser(LPCTSTR outputFileName);
	virtual ~PASER_NMEA_Parser();

	void ParseNMEASentence(string &sentence, PASER_NMEAData *myNMEAData);	
//	void ParseNMEASentence(string &sentence, GPSp *myGPSp);	
	void Test();

private:
	//CFile m_outputFile;
	int i;
    static const int reportlevel = 0;

	enum GPSSentence 
	{ 
		NMEA_NOTDEV,		
		NMEA_GPGGA,	
	        NMEA_GPGSA,
	        NMEA_GPGSV,
	        NMEA_GPRMB,
	        NMEA_GPRMC,
		NMEA_GPGLL,
		NMEA_GPVTG,
	        NMEA_GPZDA,
	        GODDE
	};
	
	map<string, GPSSentence> GPSMap;
	
	//typedef StringMap::value_type GPSMapValue;
	
	/*
	const GPSMapValue GPSMapEntries[]={
		GPSMapValue("GPGGA", NMEA_GPGGA),
		GPSMapValue("GPGSA", NMEA_GPGSA),
		GPSMapValue("GPGSV", NMEA_GPGSV),
		GPSMapValue("GPRMB", NMEA_GPRMB),
		GPSMapValue("GPRMC", NMEA_GPRMC),
		GPSMapValue("GPZDA", NMEA_GPZDA),
		GPSMapValue("GODDE", NMEA_GODDE),
	};
	*/

	void SplitSentence(string &sentence, vector<string> &result);

	void ProcessGPGGA(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGPGSA(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGPGSV(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGPRMB(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGPRMC(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGPGLL(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGPVTG(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGPZDA(string &sentence, PASER_NMEAData *myNMEAData);
	void ProcessGODDE(string &sentence, PASER_NMEAData *myNMEAData);
 

	/*
	void ParseRecursive(const char ch);
	void ParseNMEASentence(const char *addressField, const char *buf, const int bufSize);
	void ProcessGPGGA(const char *buf, const int bufSize);
	void ProcessGPGSA(const char *buf, const int bufSize);
	void ProcessGPGSV(const char *buf, const int bufSize);
	void ProcessGPRMB(const char *buf, const int bufSize);
	void ProcessGPRMC(const char *buf, const int bufSize);
	void ProcessGPZDA(const char *buf, const int bufSize);

	bool m_logging;
	*/	
	//GPSInfo m_GPSInfo;
	
};

#endif /*NMEAParser_H_*/

