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
#include "OtBinMain.v2.h"
#include "gbf.h"
#include "Common/ByteStream.h"
#include "o1party.h"
#include "psi3.h"
#include "tpsi.h"


void Channel_party_test(u64 myIdx, u64 nParties)
{
	u64 setSize = 1 << 5, psiSecParam = 40, bitSize = 128, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	std::vector<u8> dummy(nParties);
	std::vector<u8> revDummy(nParties);


	std::string name("psi");
	BtIOService ios(0);

	int btCount = nParties;
	std::vector<BtEndpoint> ep(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		dummy[i] = myIdx * 10 + i;
		if (i < myIdx)
		{
			u32 port = i * 10 + myIdx;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = myIdx * 10 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}


	std::vector<std::vector<Channel*>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
			}
		}
	}



	std::mutex printMtx1, printMtx2;
	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			if (pIdx < myIdx) {


				chls[pIdx][0]->asyncSend(&dummy[pIdx], 1);
				std::lock_guard<std::mutex> lock(printMtx1);
				std::cout << "s: " << myIdx << " -> " << pIdx << " : " << static_cast<int16_t>(dummy[pIdx]) << std::endl;

			}
			else if (pIdx > myIdx) {

				chls[pIdx][0]->recv(&revDummy[pIdx], 1);
				std::lock_guard<std::mutex> lock(printMtx2);
				std::cout << "r: " << myIdx << " <- " << pIdx << " : " << static_cast<int16_t>(revDummy[pIdx]) << std::endl;

			}
			});
	}


	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		//	if(pIdx!=myIdx)
		pThrds[pIdx].join();
	}




	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}


	ios.stop();
}



void party2psi(u64 myIdx, u64 setSize, std::vector<block> set)
{
	u64  psiSecParam = 40, bitSize = 128, numThreads = 1, nParties=2;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	PRNG prng1(_mm_set_epi32(4253465, myIdx, myIdx, myIdx)); //for test
	if(myIdx==0)
		set[2] = prng1.get<block>();;


	std::string name("psi");
	BtIOService ios(0);

	int btCount = nParties;
	std::vector<BtEndpoint> ep(nParties);

	u64 offlineTimeTot(0);
	u64 onlineTimeTot(0);
	Timer timer;

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1210 + i * 10 + myIdx;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1210 + myIdx * 10 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}


	std::vector<std::vector<Channel*>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
			}
		}
	}

	std::vector<KkrtNcoOtReceiver> otRecv(nParties);
	std::vector<KkrtNcoOtSender> otSend(nParties);

	OPPRFSender send;
	OPPRFReceiver recv;
	binSet bins;

	std::vector<std::thread>  pThrds(nParties);

	//##########################
	//### Offline Phasing
	//##########################

	auto start = timer.setTimePoint("start");

	bins.init(myIdx, nParties, setSize, psiSecParam, 1,1);
//	bins.mMaskSize = 8;
	u64 otCountSend = bins.mSimpleBins.mBins.size();
	u64 otCountRecv = bins.mCuckooBins.mBins.size();


	if (myIdx == 0) {
		//I am a sender to my next neigbour
		send.init(bins.mOpt, nParties, setSize, psiSecParam, bitSize, chls[1], otCountSend, otSend[1], otRecv[1], prng.get<block>(), false);

	}
	else if (myIdx == 1) {
		//I am a recv to my previous neigbour
		recv.init(bins.mOpt, nParties, setSize, psiSecParam, bitSize, chls[0], otCountRecv, otRecv[0], otSend[0], ZeroBlock, false);
	}


	auto initDone = timer.setTimePoint("initDone");

	//##########################
	//### Hashing
	//##########################
	bins.hashing2Bins(set, 1);
	//bins.mSimpleBins.print(myIdx, true, false, false, false);
	//bins.mCuckooBins.print(myIdx, true, false, false);

	auto hashingDone = timer.setTimePoint("hashingDone");

	//##########################
	//### Online Phasing - compute OPRF
	//##########################

#if 1
	if (myIdx == 0) {
		//I am a sender to my next neigbour
		send.getOPRFkeysfor2PSI(1, bins, chls[1], false);
		send.sendLastPSIMessage(1, bins, chls[1]);

	}
	else if (myIdx == 1) {
		//I am a recv to my previous neigbour
		recv.getOPRFkeysfor2PSI(0, bins, chls[0], false);
		recv.compute2PSI(0, bins, chls[0]);
	}






	std::cout << IoStream::lock;
	if (myIdx == 0) //sender
	{
		for (int i = 0; i < bins.mSimpleBins.mBins[0].mValOPRF[1].size(); i++)
		{

			//std::cout << bins.mSimpleBins.mBins[0].mValOPRF[1][i] << std::endl;
			//Log::out << recvPayLoads[2][i] << Log::endl;
		}
		std::cout << "------------" << std::endl;
	}
	if (myIdx == 1)
	{
		//std::cout << bins.mCuckooBins.mBins[0].mValOPRF[0] << std::endl;

		//for (int i = 0; i < bins.mCuckooBins.mBins[0].mValOPRF[0].size(); i++)
		//{
		//	//Log::out << recvPayLoads[i] << Log::endl;
		//	std::cout << sendPayLoads[i] << std::endl;
		//}
	}
	std::cout << IoStream::unlock;


	//##########################
	//### online phasing - compute intersection
	//##########################

	if (myIdx == 1) {
		Log::out << "mIntersection.size(): " << recv.mIntersection.size() << Log::endl;
		for (u64 i = 0; i < recv.mIntersection.size(); ++i)
		{
			std::cout << recv.mIntersection[i] << " - " << set[recv.mIntersection[i]] << std::endl;

		}
	}
	auto end = timer.setTimePoint("getOPRFDone");
#endif

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			for (u64 j = 0; j < numThreads; ++j)
			{
				chls[i][j]->close();
			}
		}
	}

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
			ep[i].stop();
	}


	ios.stop();
}



void party2psi_Test_Main()
{
	u64 setSize = 1 << 8, psiSecParam = 40, bitSize = 128;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector<block>mSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		mSet[i] = prng.get<block>();
	}
	std::vector<std::thread>  pThrds(2);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			//	Channel_party_test(pIdx);
			party2psi(pIdx, setSize, mSet);
			});
	}
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();


}


void O1nPSI_Test()
{
	u64 setSize = 1 << 8, psiSecParam = 40, bitSize = 128, nParties = 5;

	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			//Channel_party_test(pIdx, nParties);
			//partyO1(pIdx, nParties, setSize, GbfOkvs, secSemiHonest);
			partyO1(pIdx, nParties, setSize, PaxosOkvs, secSemiHonest);
			//partyO1(pIdx, nParties, setSize,PolyOkvs, secSemiHonest);
			});
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();


}


void nPSI3_Test()
{
	u64 setSize = 1 << 8, psiSecParam = 40, bitSize = 128;

	std::vector<std::thread>  pThrds(3);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			party_psi3(pIdx, setSize, PaxosOkvs, secSemiHonest);
			});
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();
}

void nPSI2_server_aided_Test()
{
	u64 setSize = 1 << 8, psiSecParam = 40, bitSize = 128;

	std::vector<std::thread>  pThrds(3);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			party_psi2_server_aided(pIdx, setSize, secSemiHonest);
			});
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();
}

void tPSI_Test()
{
	u64 setSize = 1 << 8, psiSecParam = 40, bitSize = 128, nParties = 10;
	u64 threshold = 7;
	std::vector<std::thread>  pThrds(nParties);

	//std::vector <block> testXORzero(nParties);

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			//Channel_party_test(pIdx, nParties);
			//partyO1(pIdx, nParties, setSize, GbfOkvs, secSemiHonest);
			tpsi_party(pIdx, nParties, threshold, setSize, PaxosOkvs, secSemiHonest);
			//partyO1(pIdx, nParties, setSize,PolyOkvs, secSemiHonest);
			});
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();

	//for (u64 pIdx = nParties - threshold+1; pIdx < nParties; ++pIdx)
	//	testXORzero[nParties - threshold] = testXORzero[nParties - threshold] ^testXORzero[pIdx];

	//std::cout << testXORzero[nParties - threshold] << " final \n";
}
