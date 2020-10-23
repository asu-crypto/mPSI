#pragma once
#include <Common/Defines.h>
#include <Network/Channel.h>
#include <NChooseOne/NcoOtExt.h>
#include "Crypto/PRNG.h"
//#include <cryptoTools/Common/CuckooIndex.h>

namespace osuCrypto
{


	class KkrtPsiSender
	{
	public:
		KkrtPsiSender();
		~KkrtPsiSender();

		u64 mSenderSize, mRecverSize, mStatSecParam;
        PRNG mPrng;
        std::vector<u64>mPermute;

		//SimpleIndex mIndex;
       // CuckooParam mParams;
		block mHashingSeed;

        NcoOtExtSender* mOtSender;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, std::vector<Channel*> chls, NcoOtExtSender& otSender, block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel & chl0, NcoOtExtSender& otSender, block seed);

		//void sendInput(std::vector<block> inputs, Channel& chl);
		//void sendInput(std::vector<block> inputs, std::vector<Channel> chls);


	};

}