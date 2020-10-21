#include "OT_Tests.h"

#include "TwoChooseOne/OTExtInterface.h"

#include "Tools/Tools.h"
#include "Tools/LinearCode.h"
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"
#include "Common/Log.h"

#include "TwoChooseOne/IknpOtExtReceiver.h"
#include "TwoChooseOne/IknpOtExtSender.h"

#include "TwoChooseOne/KosOtExtReceiver.h"
#include "TwoChooseOne/KosOtExtSender.h"

#include "TwoChooseOne/LzKosOtExtReceiver.h"
#include "TwoChooseOne/LzKosOtExtSender.h"

#include "NChooseOne/KkrtNcoOtReceiver.h"
#include "NChooseOne/KkrtNcoOtSender.h"

#include "Common.h"
#include <thread>
#include <vector>
#include <numeric>
#include <iostream>
#include <fstream>
#include "OPPRF/OPPRFReceiver.h"
#include "OPPRF/OPPRFSender.h"
#include "Common/Log.h"
#include "Common/Log1.h"

#ifdef GetMessage
#undef GetMessage
#endif

#pragma warning(disable: 4800)

using namespace osuCrypto;


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

bool is_in_dual_area(u64 startIdx, u64 endIdx, u64 numIdx, u64 checkIdx) {
	bool res = false;
	if (startIdx <= endIdx)
	{
		if (startIdx <= checkIdx && checkIdx <= endIdx)
			res = true;
	}
	else //crosing 0, e.i, areas: startIdx....n-1, 0...endIdx
	{
		if ((0 <= checkIdx && checkIdx <= endIdx) //0...endIdx
			|| (startIdx <= checkIdx && checkIdx <= numIdx))
			//startIdx...n-1
			res = true;
	}
	return res;
}


//leader is n-1
void partyO1(u64 myIdx, u64 nParties, u64 tParties, u64 setSize, u64 nTrials)
{
#if 0
	u64 opt = 0;
	std::fstream runtime;
	u64 leaderIdx = nParties - 1; //leader party

	if (myIdx == 0)
		runtime.open("./runtime_client.txt", runtime.app | runtime.out);

	if (myIdx == leaderIdx)
		runtime.open("./runtime_leader.txt", runtime.app | runtime.out);


#pragma region setup

	u64 ttParties = tParties;
	if (tParties == nParties - 1)//it is sufficient to prevent n-2 ssClientTimecorrupted parties since if n-1 corrupted and only now the part of intersection if all has x, i.e. x is in intersection. 
		ttParties = tParties - 1;
	else if (tParties < 1) //make sure to do ss with at least one client
		ttParties = 1;

	u64 nSS = nParties - 1; //n-2 parties joinly operated secrete sharing
	int tSS = ttParties; //ss with t next  parties, and last for leader => t+1  


	u64 offlineAvgTime(0), hashingAvgTime(0), getOPRFAvgTime(0),
		ss2DirAvgTime(0), ssRoundAvgTime(0), intersectionAvgTime(0), onlineAvgTime(0);

	u64  psiSecParam = 40, bitSize = 128, numThreads = 1;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));

	std::string name("psi");
	BtIOService ios(0);


	std::vector<BtEndpoint> ep(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			u32 port = 1200 + i * 100 + myIdx;;//get the same port; i=1 & pIdx=2 =>port=102
			ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
		}
		else if (i > myIdx)
		{
			u32 port = 1200 + myIdx * 100 + i;//get the same port; i=2 & pIdx=1 =>port=102
			ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
		}
	}

	std::vector<std::vector<Channel*>> chls(nParties);
	std::vector<u8> dummy(nParties);
	std::vector<u8> revDummy(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		dummy[i] = myIdx * 10 + i;

		if (i != myIdx) {
			chls[i].resize(numThreads);
			for (u64 j = 0; j < numThreads; ++j)
			{
				//chls[i][j] = &ep[i].addChannel("chl" + std::to_string(j), "chl" + std::to_string(j));
				chls[i][j] = &ep[i].addChannel(name, name);
				//chls[i][j].mEndpoint;



			}
		}
	}


	u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;
	u64 nextNeighbor = (myIdx + 1) % nParties;
	u64 prevNeighbor = (myIdx - 1 + nParties) % nParties;
	u64 num_intersection;
	double dataSent, Mbps, MbpsRecv, dataRecv;
#pragma endregion

	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	u64 expected_intersection;


	for (u64 idxTrial = 0; idxTrial < nTrials; idxTrial++)
	{
#pragma region input
		std::vector<block> set(setSize);

		std::vector<std::vector<block>>
			sendPayLoads(ttParties + 1), //include the last PayLoads to leader
			recvPayLoads(ttParties); //received form clients

		block blk_rand = prngSame.get<block>();
		expected_intersection = (*(u64*)&blk_rand) % setSize;

		for (u64 i = 0; i < expected_intersection; ++i)
		{
			set[i] = prngSame.get<block>();
		}

		for (u64 i = expected_intersection; i < setSize; ++i)
		{
			set[i] = prngDiff.get<block>();
		}





#ifdef PRINT	
		std::cout << IoStream::lock;
		if (myIdx != leaderIdx) {
			for (u64 i = 0; i < setSize; ++i)
			{
				block check = ZeroBlock;
				for (u64 idxP = 0; idxP < ttParties + 1; ++idxP)
				{
					//if (idxP != myIdx)
					check = check ^ sendPayLoads[idxP][i];
				}
				if (memcmp((u8*)&check, &ZeroBlock, sizeof(block)))
					std::cout << "Error ss values: myIdx: " << myIdx
					<< " value: " << check << std::endl;
			}
		}
		std::cout << IoStream::unlock;
#endif
#pragma endregion
		u64 num_threads = nParties - 1; //except P0, and my
		bool isDual = true;
		u64 idx_start_dual = 0;
		u64 idx_end_dual = 0;
		u64 t_prev_shift = tSS;

		if (myIdx != leaderIdx) {
			if (2 * tSS < nSS)
			{
				num_threads = 2 * tSS + 1;
				isDual = false;
			}
			else {
				idx_start_dual = (myIdx - tSS + nSS) % nSS;
				idx_end_dual = (myIdx + tSS) % nSS;
			}

			/*std::cout << IoStream::lock;
			std::cout << myIdx << "| " << idx_start_dual << " " << idx_end_dual << "\n";
			std::cout << IoStream::unlock;*/
		}
		std::vector<std::thread>  pThrds(num_threads);

		std::vector<KkrtNcoOtReceiver> otRecv(nParties);
		std::vector<KkrtNcoOtSender> otSend(nParties);
		std::vector<OPPRFSender> send(nParties);
		std::vector<OPPRFReceiver> recv(nParties);

		if (myIdx == leaderIdx)
		{
			/*otRecv.resize(nParties - 1);
			otSend.resize(nParties - 1);
			send.resize(nParties - 1);
			recv.resize(nParties - 1);*/
			pThrds.resize(nParties - 1);
		}



		binSet bins;

		//##########################
		//### Offline Phasing
		//##########################
		Timer timer;
		auto start = timer.setTimePoint("start");

		if (myIdx != leaderIdx) {//generate share of zero for leader myIDx!=n-1		
			for (u64 idxP = 0; idxP < ttParties; ++idxP)
			{
				sendPayLoads[idxP].resize(setSize);
				for (u64 i = 0; i < setSize; ++i)
				{
					sendPayLoads[idxP][i] = prng.get<block>();
				}
			}

			sendPayLoads[ttParties].resize(setSize); //share to leader at second phase
			for (u64 i = 0; i < setSize; ++i)
			{
				sendPayLoads[ttParties][i] = ZeroBlock;
				for (u64 idxP = 0; idxP < ttParties; ++idxP)
				{
					sendPayLoads[ttParties][i] =
						sendPayLoads[ttParties][i] ^ sendPayLoads[idxP][i];
				}
			}
			for (u64 idxP = 0; idxP < recvPayLoads.size(); ++idxP)
			{
				recvPayLoads[idxP].resize(setSize);
			}

		}
		else
		{
			//leader: dont send; only receive ss from clients
			sendPayLoads.resize(0);//
			recvPayLoads.resize(nParties - 1);
			for (u64 idxP = 0; idxP < recvPayLoads.size(); ++idxP)
			{
				recvPayLoads[idxP].resize(setSize);
			}

		}


		bins.init(myIdx, nParties, setSize, psiSecParam, opt);
		u64 otCountSend = bins.mSimpleBins.mBins.size();
		u64 otCountRecv = bins.mCuckooBins.mBins.size();


#pragma region base OT
		//##########################
		//### Base OT
		//##########################

		if (myIdx != leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < tSS; ++pIdx)
			{
				u64 prevIdx = (myIdx - pIdx - 1 + nSS) % nSS;

				if (!(isDual && is_in_dual_area(idx_start_dual, idx_end_dual, nSS, prevIdx)))
				{
					u64 thr = t_prev_shift + pIdx;

					pThrds[thr] = std::thread([&, prevIdx, thr]() {

						//chls[prevIdx][0]->recv(&revDummy[prevIdx], 1);
						//std::cout << IoStream::lock;
						//std::cout << myIdx << "| : " << "| thr[" << thr << "]:" << prevIdx << " --> " << myIdx << ": " << static_cast<int16_t>(revDummy[prevIdx]) << "\n";
						//std::cout << IoStream::unlock;


						//prevIdx << " --> " << myIdx
						recv[prevIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[prevIdx], otCountRecv, otRecv[prevIdx], otSend[prevIdx], ZeroBlock, false);

						});



				}
			}

			for (u64 pIdx = 0; pIdx < tSS; ++pIdx)
			{
				u64 nextIdx = (myIdx + pIdx + 1) % nSS;

				if ((isDual && is_in_dual_area(idx_start_dual, idx_end_dual, nSS, nextIdx))) {

					pThrds[pIdx] = std::thread([&, nextIdx, pIdx]() {


						//dual myIdx << " <-> " << nextIdx 
						if (myIdx < nextIdx)
						{
							//chls[nextIdx][0]->asyncSend(&dummy[nextIdx], 1);
							//std::cout << IoStream::lock;
							//std::cout << myIdx << "| d: " << "| thr[" << pIdx << "]:" << myIdx << " <->> " << nextIdx << ": " << static_cast<int16_t>(dummy[nextIdx]) << "\n";
							//std::cout << IoStream::unlock;

							send[nextIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[nextIdx], otCountSend, otSend[nextIdx], otRecv[nextIdx], prng.get<block>(), true);
						}
						else if (myIdx > nextIdx) //by index
						{
							/*						chls[nextIdx][0]->recv(&revDummy[nextIdx], 1);

							std::cout << IoStream::lock;
							std::cout << myIdx << "| d: " << "| thr[" << pIdx << "]:" << myIdx << " <<-> " << nextIdx << ": " << static_cast<int16_t>(revDummy[nextIdx]) << "\n";
							std::cout << IoStream::unlock;*/

							recv[nextIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[nextIdx], otCountRecv, otRecv[nextIdx], otSend[nextIdx], ZeroBlock, true);
						}
						});

				}
				else
				{
					pThrds[pIdx] = std::thread([&, nextIdx, pIdx]() {

						//chls[nextIdx][0]->asyncSend(&dummy[nextIdx], 1);
						//std::cout << IoStream::lock;
						//std::cout << myIdx << "| : " << "| thr[" << pIdx << "]:" << myIdx << " -> " << nextIdx << ": " << static_cast<int16_t>(dummy[nextIdx]) << "\n";
						//std::cout << IoStream::unlock;
						send[nextIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[nextIdx], otCountSend, otSend[nextIdx], otRecv[nextIdx], prng.get<block>(), false);
						});
				}
			}

			//last thread for connecting with leader
			u64 tLeaderIdx = pThrds.size() - 1;
			pThrds[pThrds.size() - 1] = std::thread([&, leaderIdx]() {

				//	chls[leaderIdx][0]->asyncSend(&dummy[leaderIdx], 1);

				//std::cout << IoStream::lock;
				//std::cout << myIdx << "| : " << "| thr[" << pThrds.size() - 1 << "]:" << myIdx << " --> " << leaderIdx << ": " << static_cast<int16_t>(dummy[leaderIdx]) << "\n";
				//std::cout << IoStream::unlock;

				send[leaderIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[leaderIdx], otCountSend, otSend[leaderIdx], otRecv[leaderIdx], prng.get<block>(), false);
				});

		}
		else
		{ //leader party 

			for (u64 pIdx = 0; pIdx < nSS; ++pIdx)
			{
				pThrds[pIdx] = std::thread([&, pIdx]() {
					/*				chls[pIdx][0]->recv(&revDummy[pIdx], 1);
					std::cout << IoStream::lock;
					std::cout << myIdx << "| : " << "| thr[" << pIdx << "]:" << pIdx << " --> " << myIdx << ": " << static_cast<int16_t>(revDummy[pIdx]) << "\n";
					std::cout << IoStream::unlock;*/

					recv[pIdx].init(opt, nParties, setSize, psiSecParam, bitSize, chls[pIdx], otCountRecv, otRecv[pIdx], otSend[pIdx], ZeroBlock, false);
					});

			}
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

		auto initDone = timer.setTimePoint("initDone");


#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			Log::out << myIdx << "| -> " << otSend[1].mGens[0].get<block>() << Log::endl;
			if (otRecv[1].hasBaseOts())
			{
				Log::out << myIdx << "| <- " << otRecv[1].mGens[0][0].get<block>() << Log::endl;
				Log::out << myIdx << "| <- " << otRecv[1].mGens[0][1].get<block>() << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}
		if (myIdx == 1)
		{
			if (otSend[0].hasBaseOts())
				Log::out << myIdx << "| -> " << otSend[0].mGens[0].get<block>() << Log::endl;

			Log::out << myIdx << "| <- " << otRecv[0].mGens[0][0].get<block>() << Log::endl;
			Log::out << myIdx << "| <- " << otRecv[0].mGens[0][1].get<block>() << Log::endl;
		}

		if (isDual)
		{
			if (myIdx == 0)
			{
				Log::out << myIdx << "| <->> " << otSend[tSS].mGens[0].get<block>() << Log::endl;
				if (otRecv[tSS].hasBaseOts())
				{
					Log::out << myIdx << "| <<-> " << otRecv[tSS].mGens[0][0].get<block>() << Log::endl;
					Log::out << myIdx << "| <<-> " << otRecv[tSS].mGens[0][1].get<block>() << Log::endl;
				}
				Log::out << "------------" << Log::endl;
			}
			if (myIdx == tSS)
			{
				if (otSend[0].hasBaseOts())
					Log::out << myIdx << "| <->> " << otSend[0].mGens[0].get<block>() << Log::endl;

				Log::out << myIdx << "| <<-> " << otRecv[0].mGens[0][0].get<block>() << Log::endl;
				Log::out << myIdx << "| <<-> " << otRecv[0].mGens[0][1].get<block>() << Log::endl;
			}
		}
		std::cout << IoStream::unlock;
#endif

#pragma endregion


		//##########################
		//### Hashing
		//##########################

		bins.hashing2Bins(set, 1);
		/*if(myIdx==0)
		bins.mSimpleBins.print(myIdx, true, false, false, false);
		if (myIdx == 1)
		bins.mCuckooBins.print(myIdx, true, false, false);*/

		auto hashingDone = timer.setTimePoint("hashingDone");

#pragma region compute OPRF

		//##########################
		//### Online Phasing - compute OPRF
		//##########################

		pThrds.clear();
		pThrds.resize(num_threads);
		if (myIdx == leaderIdx)
		{
			pThrds.resize(nParties - 1);
		}

		if (myIdx != leaderIdx)
		{
			for (u64 pIdx = 0; pIdx < tSS; ++pIdx)
			{
				u64 prevIdx = (myIdx - pIdx - 1 + nSS) % nSS;

				if (!(isDual && is_in_dual_area(idx_start_dual, idx_end_dual, nSS, prevIdx)))
				{
					u64 thr = t_prev_shift + pIdx;

					pThrds[thr] = std::thread([&, prevIdx]() {

						//prevIdx << " --> " << myIdx
						recv[prevIdx].getOPRFkeys(prevIdx, bins, chls[prevIdx], false);



						});
				}
			}

			for (u64 pIdx = 0; pIdx < tSS; ++pIdx)
			{
				u64 nextIdx = (myIdx + pIdx + 1) % nSS;

				if ((isDual && is_in_dual_area(idx_start_dual, idx_end_dual, nSS, nextIdx))) {

					pThrds[pIdx] = std::thread([&, nextIdx]() {
						//dual myIdx << " <-> " << nextIdx 
						if (myIdx < nextIdx)
						{
							send[nextIdx].getOPRFkeys(nextIdx, bins, chls[nextIdx], true);
						}
						else if (myIdx > nextIdx) //by index
						{
							recv[nextIdx].getOPRFkeys(nextIdx, bins, chls[nextIdx], true);
						}
						});

				}
				else
				{
					pThrds[pIdx] = std::thread([&, nextIdx]() {
						send[nextIdx].getOPRFkeys(nextIdx, bins, chls[nextIdx], false);
						});
				}
			}

			//last thread for connecting with leader
			pThrds[pThrds.size() - 1] = std::thread([&, leaderIdx]() {
				send[leaderIdx].getOPRFkeys(leaderIdx, bins, chls[leaderIdx], false);
				});

		}
		else
		{ //leader party 
			for (u64 pIdx = 0; pIdx < nSS; ++pIdx)
			{
				pThrds[pIdx] = std::thread([&, pIdx]() {
					recv[pIdx].getOPRFkeys(pIdx, bins, chls[pIdx], false);

					});
			}
		}

		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();

		auto getOPRFDone = timer.setTimePoint("getOPRFDone");


#ifdef BIN_PRINT

		if (myIdx == 0)
		{
			bins.mSimpleBins.print(1, true, true, false, false);
		}
		if (myIdx == 1)
		{
			bins.mCuckooBins.print(0, true, true, false);
		}

		if (isDual)
		{
			if (myIdx == 0)
			{
				bins.mCuckooBins.print(tSS, true, true, false);
			}
			if (myIdx == tSS)
			{
				bins.mSimpleBins.print(0, true, true, false, false);
			}
		}

#endif
#pragma endregion

#pragma region SS

		//##########################
		//### online phasing - secretsharing
		//##########################

		pThrds.clear();

		if (myIdx != leaderIdx)
		{
			pThrds.resize(num_threads);
			for (u64 pIdx = 0; pIdx < tSS; ++pIdx)
			{
				u64 prevIdx = (myIdx - pIdx - 1 + nSS) % nSS;

				if (!(isDual && is_in_dual_area(idx_start_dual, idx_end_dual, nSS, prevIdx)))
				{
					u64 thr = t_prev_shift + pIdx;

					pThrds[thr] = std::thread([&, prevIdx, pIdx]() {

						//prevIdx << " --> " << myIdx
						recv[prevIdx].recvSSTableBased(prevIdx, bins, recvPayLoads[pIdx], chls[prevIdx]);

						});
				}
			}

			for (u64 pIdx = 0; pIdx < tSS; ++pIdx)
			{
				u64 nextIdx = (myIdx + pIdx + 1) % nSS;

				if ((isDual && is_in_dual_area(idx_start_dual, idx_end_dual, nSS, nextIdx))) {

					pThrds[pIdx] = std::thread([&, nextIdx, pIdx]() {
						//dual myIdx << " <-> " << nextIdx 
						//send OPRF can receive payload
						if (myIdx < nextIdx)
						{
							send[nextIdx].sendSSTableBased(nextIdx, bins, sendPayLoads[pIdx], chls[nextIdx]);

							send[nextIdx].recvSSTableBased(nextIdx, bins, recvPayLoads[pIdx], chls[nextIdx]);
						}
						else if (myIdx > nextIdx) //by index
						{
							recv[nextIdx].recvSSTableBased(nextIdx, bins, recvPayLoads[pIdx], chls[nextIdx]);

							recv[nextIdx].sendSSTableBased(nextIdx, bins, sendPayLoads[pIdx], chls[nextIdx]);

						}
						});

				}
				else
				{
					pThrds[pIdx] = std::thread([&, nextIdx, pIdx]() {
						send[nextIdx].sendSSTableBased(nextIdx, bins, sendPayLoads[pIdx], chls[nextIdx]);
						});
				}
			}

			//last thread for connecting with leader
			pThrds[pThrds.size() - 1] = std::thread([&, leaderIdx]() {
				//send[leaderIdx].getOPRFKeys(0,leaderIdx, bins, chls[leaderIdx], false);
				});

			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
				pThrds[pIdx].join();
		}

		auto getSsClientsDone = timer.setTimePoint("secretsharingClientDone");


#ifdef PRINT
		std::cout << IoStream::lock;
		if (myIdx == 0)
		{
			for (int i = 0; i < 3; i++)
			{
				block temp = ZeroBlock;
				memcpy((u8*)&temp, (u8*)&sendPayLoads[0][i], maskSize);
				Log::out << myIdx << "| -> 1: (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}
		if (myIdx == 1)
		{
			for (int i = 0; i < 3; i++)
			{
				block temp = ZeroBlock;
				memcpy((u8*)&temp, (u8*)&recvPayLoads[0][i], maskSize);
				Log::out << myIdx << "| <- 0: (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
		}

		if (isDual)
		{
			/*if (myIdx == 0)
			{
			for (int i = 0; i < 3; i++)
			{
			block temp = ZeroBlock;
			memcpy((u8*)&temp, (u8*)&recvPayLoads[tSS][i], maskSize);
			Log::out << myIdx << "| <- "<< tSS<<": (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
			}
			if (myIdx == tSS)
			{
			for (int i = 0; i < 3; i++)
			{
			block temp = ZeroBlock;
			memcpy((u8*)&temp, (u8*)&sendPayLoads[0][i], maskSize);
			Log::out << myIdx << "| -> 0: (" << i << ", " << temp << ")" << Log::endl;
			}
			Log::out << "------------" << Log::endl;
			}*/
		}

		std::cout << IoStream::unlock;
#endif
#pragma endregion

		//##########################
		//### online phasing - send XOR of zero share to leader
		//##########################
		pThrds.clear();

		if (myIdx != leaderIdx)
		{

			for (u64 i = 0; i < setSize; ++i)
			{
				//xor all received share
				for (u64 idxP = 0; idxP < ttParties; ++idxP)
				{
					sendPayLoads[ttParties][i] = sendPayLoads[ttParties][i] ^ recvPayLoads[idxP][i];
				}
			}
			//send to leader
			send[leaderIdx].sendSSTableBased(leaderIdx, bins, sendPayLoads[ttParties], chls[leaderIdx]);
		}
		else
		{
			pThrds.resize(nParties - 1);

			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx) {
				pThrds[pIdx] = std::thread([&, pIdx]() {
					recv[pIdx].recvSSTableBased(pIdx, bins, recvPayLoads[pIdx], chls[pIdx]);
					});
			}

			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
				pThrds[pIdx].join();
		}


		auto getSSLeaderDone = timer.setTimePoint("leaderGetXorDone");



		//##########################
		//### online phasing - compute intersection
		//##########################

		std::vector<u64> mIntersection;
		if (myIdx == leaderIdx) {

			//u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;

			for (u64 i = 0; i < setSize; ++i)
			{

				//xor all received share
				block sum = ZeroBlock;
				for (u64 idxP = 0; idxP < nParties - 1; ++idxP)
				{
					sum = sum ^ recvPayLoads[idxP][i];
				}

				if (!memcmp((u8*)&ZeroBlock, &sum, bins.mMaskSize))
				{
					mIntersection.push_back(i);
				}
			}

		}
		auto getIntersection = timer.setTimePoint("getIntersection");

		std::cout << IoStream::lock;

		if (myIdx == 0 || myIdx == 1 || myIdx == leaderIdx) {
			auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(initDone - start).count();
			auto hashingTime = std::chrono::duration_cast<std::chrono::milliseconds>(hashingDone - initDone).count();
			auto getOPRFTime = std::chrono::duration_cast<std::chrono::milliseconds>(getOPRFDone - hashingDone).count();
			auto ssClientTime = std::chrono::duration_cast<std::chrono::milliseconds>(getSsClientsDone - getOPRFDone).count();
			auto ssServerTime = std::chrono::duration_cast<std::chrono::milliseconds>(getSSLeaderDone - getSsClientsDone).count();
			auto intersectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(getIntersection - getSSLeaderDone).count();

			double onlineTime = hashingTime + getOPRFTime + ssClientTime + ssServerTime + intersectionTime;

			double time = offlineTime + onlineTime;
			time /= 1000;


			dataSent = 0;
			dataRecv = 0;
			Mbps = 0;
			MbpsRecv = 0;
			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						dataSent += chls[i][j]->getTotalDataSent();
						dataRecv += chls[i][j]->getTotalDataRecv();
					}
				}
			}

			Mbps = dataSent * 8 / time / (1 << 20);
			MbpsRecv = dataRecv * 8 / time / (1 << 20);

			for (u64 i = 0; i < nParties; ++i)
			{
				if (i != myIdx) {
					chls[i].resize(numThreads);
					for (u64 j = 0; j < numThreads; ++j)
					{
						chls[i][j]->resetStats();
					}
				}
			}

			if (myIdx == 0 || myIdx == 1)
			{
				std::cout << "Client Idx: " << myIdx << "\n";
			}
			else
			{
				std::cout << "\nLeader Idx: " << myIdx << "\n";
			}

			if (myIdx == leaderIdx) {
				Log::out << "#Output Intersection: " << mIntersection.size() << Log::endl;
				Log::out << "#Expected Intersection: " << expected_intersection << Log::endl;
				num_intersection = mIntersection.size();
			}

			std::cout << "setSize: " << setSize << "\n"
				<< "offlineTime:  " << offlineTime << " ms\n"
				<< "hashingTime:  " << hashingTime << " ms\n"
				<< "getOPRFTime:  " << getOPRFTime << " ms\n"
				<< "ss2DirTime:  " << ssClientTime << " ms\n"
				<< "ssRoundTime:  " << ssServerTime << " ms\n"
				<< "intersection:  " << intersectionTime << " ms\n"
				<< "onlineTime:  " << onlineTime << " ms\n"
				//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
				<< "Total time: " << time << " s\n"
				//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
				//<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
				<< "------------------\n";




			offlineAvgTime += offlineTime;
			hashingAvgTime += hashingTime;
			getOPRFAvgTime += getOPRFTime;
			ss2DirAvgTime += ssClientTime;
			ssRoundAvgTime += ssServerTime;
			intersectionAvgTime += intersectionTime;
			onlineAvgTime += onlineTime;

		}
		std::cout << IoStream::unlock;
	}

	std::cout << IoStream::lock;
	if (myIdx == 0 || myIdx == leaderIdx) {
		double avgTime = (offlineAvgTime + onlineAvgTime);
		avgTime /= 1000;

		std::cout << "=========avg==========\n";
		runtime << "=========avg==========\n";
		runtime << "numParty: " << nParties
			<< "  numCorrupted: " << tParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n";

		if (myIdx == 0)
		{
			std::cout << "Client Idx: " << myIdx << "\n";
			runtime << "Client Idx: " << myIdx << "\n";

		}
		else
		{
			std::cout << "Leader Idx: " << myIdx << "\n";
			Log::out << "#Output Intersection: " << num_intersection << Log::endl;
			Log::out << "#Expected Intersection: " << expected_intersection << Log::endl;

			runtime << "Leader Idx: " << myIdx << "\n";
			runtime << "#Output Intersection: " << num_intersection << "\n";
			runtime << "#Expected Intersection: " << expected_intersection << "\n";
		}



		std::cout << "numParty: " << nParties
			<< "  numCorrupted: " << tParties
			<< "  setSize: " << setSize
			<< "  nTrials:" << nTrials << "\n"
			<< "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			<< "ssClientTime:  " << ss2DirAvgTime / nTrials << " ms\n"
			<< "ssLeaderTime:  " << ssRoundAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime / nTrials << " s\n"
			//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			//<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";

		runtime << "offlineTime:  " << offlineAvgTime / nTrials << " ms\n"
			<< "hashingTime:  " << hashingAvgTime / nTrials << " ms\n"
			<< "getOPRFTime:  " << getOPRFAvgTime / nTrials << " ms\n"
			<< "ssClientTime:  " << ss2DirAvgTime / nTrials << " ms\n"
			<< "ssLeaderTime:  " << ssRoundAvgTime / nTrials << " ms\n"
			<< "intersection:  " << intersectionAvgTime / nTrials << " ms\n"
			<< "onlineTime:  " << onlineAvgTime / nTrials << " ms\n"
			//<< "Bandwidth: Send: " << Mbps << " Mbps,\t Recv: " << MbpsRecv << " Mbps\n"
			<< "Total time: " << avgTime / nTrials << " s\n"
			//<< "Total Comm: Send:" << (dataSent / std::pow(2.0, 20)) << " MB"
			//<< "\t Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB\n"
			<< "------------------\n";
		runtime.close();
	}
	std::cout << IoStream::unlock;



	/*if (myIdx == 0) {
	double avgTime = (offlineAvgTime + onlineAvgTime);
	avgTime /= 1000;
	std::cout << "=========avg==========\n"
	<< "setSize: " << setSize << "\n"
	<< "offlineTime:  " << offlineAvgTime / numTrial << " ms\n"
	<< "hashingTime:  " << hashingAvgTime / numTrial << " ms\n"
	<< "getOPRFTime:  " << getOPRFAvgTime / numTrial << " ms\n"
	<< "ss2DirTime:  " << ss2DirAvgTime << " ms\n"
	<< "ssRoundTime:  " << ssRoundAvgTime << " ms\n"
	<< "intersection:  " << intersectionAvgTime / numTrial << " ms\n"
	<< "onlineTime:  " << onlineAvgTime / numTrial << " ms\n"
	<< "Total time: " << avgTime / numTrial << " s\n";
	runtime << "setSize: " << setSize << "\n"
	<< "offlineTime:  " << offlineAvgTime / numTrial << " ms\n"
	<< "hashingTime:  " << hashingAvgTime / numTrial << " ms\n"
	<< "getOPRFTime:  " << getOPRFAvgTime / numTrial << " ms\n"
	<< "ss2DirTime:  " << ss2DirAvgTime << " ms\n"
	<< "ssRoundTime:  " << ssRoundAvgTime << " ms\n"
	<< "intersection:  " << intersectionAvgTime / numTrial << " ms\n"
	<< "onlineTime:  " << onlineAvgTime / numTrial << " ms\n"
	<< "Total time: " << avgTime / numTrial << " s\n";
	runtime.close();
	}
	*/
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
#endif
}


void O1nPSI_Test()
{
	u64 setSize = 1 << 5, psiSecParam = 40, bitSize = 128;

	u64 nParties = 5;
	u64 tParties = 2;


	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		{
			pThrds[pIdx] = std::thread([&, pIdx]() {
				//Channel_party_test(pIdx, nParties);
				partyO1(pIdx, nParties, tParties, setSize, 1);
				});
		}
	}
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();


}