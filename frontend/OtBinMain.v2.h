#pragma once

#include "Crypto/PRNG.h"
#include "Network/BtEndpoint.h" 

#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/OPPRFSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "Common/Defines.h"
#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include "NChooseOne/Oos/OosNcoOtReceiver.h"
#include "NChooseOne/Oos/OosNcoOtSender.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <numeric>
#include <iostream>


void Channel_party_test(u64 myIdx, u64 nParties);
void O1nPSI_Test();

//void party_test();
void party2psi_Test_Main();
//void GbfTest();

void nPSI3_Test();
void nPSI2_server_aided_Test();
void tPSI_Test();
//void Channel_party_test(u64 myIdx, u64 nParties)