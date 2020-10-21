#pragma once



#include "Network/Channel.h"

#define GbfOkvs 0
#define PolyOkvs 1

#define secMalicious 0
#define secSemiHonest 1

void senderGetLatency(osuCrypto::Channel& chl);

void recverGetLatency(osuCrypto::Channel& chl);
