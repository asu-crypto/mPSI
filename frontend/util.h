#pragma once



#include "Network/Channel.h"
#include <fstream>

#define GbfOkvs 0
#define PolyOkvs 1
#define	TableOPPRF 0

#define secMalicious 0
#define secSemiHonest 1

#define okvsHashFunctions 40
#define okvsLengthScale 60

#define isNTLThreadSafe 0

void InitDebugPrinting(std::string file = "../testoutput.txt");

void senderGetLatency(osuCrypto::Channel& chl);

void recverGetLatency(osuCrypto::Channel& chl);
