#pragma once
#include "Crypto/PRNG.h"
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include <set>
#include "gbf.h"

using namespace osuCrypto;


//for party 0->t-1
inline void user_encode(std::vector<block> inputSet, const std::vector<block> aesKeys, std::vector<block>& okvsTable, u64 party_t_id, u64 nParties, u64 type_okvs, u64 type_security)
{

	std::vector<block> setValues(inputSet.size(), ZeroBlock), hashInputSet(inputSet.size());
	std::vector<AES> vectorAES(nParties); //but only use n-t -> n
	std::vector <std::vector<block>> ciphertexts(nParties); //ciphertexts[idxParty][idxItem], only use idxParty: n-t -> n

	for (u64 i = party_t_id; i < nParties; ++i)
	{
		vectorAES[i].setKey(aesKeys[i]);
		ciphertexts[i].resize(inputSet.size());
	}

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); //H(xi)

	for (u64 i = party_t_id; i < nParties; ++i)
		vectorAES[i].ecbEncBlocks(hashInputSet.data(), hashInputSet.size(), ciphertexts[i].data()); //compute F_ki(H(xi))

	for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
		for (u64 idxParty = party_t_id; idxParty < nParties; ++idxParty)
			setValues[idxItem] = setValues[idxItem] ^ ciphertexts[idxParty][idxItem];

	//std::cout << IoStream::lock;
	//for (u64 i = 0; i < 2; i++)
	//	std::cout << setValues[i] << " - encode party 1 - " << i << std::endl;
	//std::cout << IoStream::unlock;

	if (type_okvs == GbfOkvs)
		GbfEncode(inputSet, setValues, okvsTable);
	else if (type_okvs == PolyOkvs)
		PolyEncode(inputSet, setValues, okvsTable);

	/*std::cout << IoStream::lock;
	for (u64 i = 0; i < 2; i++)
	{
		std::cout << okvsTable[i] << " - okvsTable - " << i << std::endl;
	}
	std::cout << IoStream::unlock;*/

	//if (type_okvs == PolyOkvs) //TODO
	//std::vector<block> inputSet2PSI(inputSet.size(), ZeroBlock);
	//GbfDecode(okvsTable, inputSet, inputSet2PSI); //Decode(okvsTable, x) where okvsTable is received from party 1
	//std::cout << IoStream::lock;
	//for (u64 i = 0; i < 2; i++)
	//{
	//	std::cout << inputSet2PSI[i] << " - setValues decode party 1 - " << i << std::endl;
	//}
	//std::cout << IoStream::unlock;
}

//for party t
inline void partyt_decode(const std::vector<block> inputSet, const std::vector <std::vector<block>> okvsTables, std::vector<block>& inputSet2ZeroXOR, u64 type_okvs, u64 type_security)
{
	inputSet2ZeroXOR.resize(inputSet.size(), ZeroBlock);
	std::vector<block> hashInputSet(inputSet.size());
	std::vector<block> decodeValues;

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); //H(xi)
	
	for (u64 idxParty = 0; idxParty < okvsTables.size(); idxParty++)
	{
		if (type_okvs == GbfOkvs)
			GbfDecode(okvsTables[idxParty], hashInputSet, decodeValues); //Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]
		else if (type_okvs == PolyOkvs)
			PolyDecode(okvsTables[idxParty], hashInputSet, decodeValues); //Decode(okvsTable, x) where okvsTable is received from idxParty [0->t-1]
	
		for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
			inputSet2ZeroXOR[idxItem] = decodeValues[idxItem] ^ inputSet2ZeroXOR[idxItem];  //xor all values 
	}

	/*std::cout << IoStream::lock;
	for (u64 i = 0; i < 2; i++)
		std::cout << inputSet2PSI[i] << " - decode partyn - " << i << std::endl;
	std::cout << IoStream::unlock;*/

	//for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
	//	inputSet2PSI[idxItem] = inputSet2PSI[idxItem] ^ inputSet[idxItem]; //simulate x||F(x) xor all decodes
}

//for server t->n: compute XOR F(key_user, value)
inline void server_prf(const std::vector<block> inputSet, const std::vector<block> aesKeys, std::vector<block>& inputSet2ZeroXOR, u64 type_okvs, u64 type_security)
{
	inputSet2ZeroXOR.resize(inputSet.size(), ZeroBlock);
	std::vector<block> hashInputSet(inputSet.size());
	std::vector<AES> vectorAES(aesKeys.size()); //but only use n-t -> n
	std::vector <std::vector<block>> ciphertexts(aesKeys.size());

	for (u64 i = 0; i < aesKeys.size(); ++i)
	{
		vectorAES[i].setKey(aesKeys[i]);
		ciphertexts[i].resize(inputSet.size());
	}

	hashInputSet = inputSet;
	if (type_security == secMalicious)
		mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); //H(xi)

	for (u64 i = 0; i < aesKeys.size(); ++i)
		vectorAES[i].ecbEncBlocks(hashInputSet.data(), hashInputSet.size(), ciphertexts[i].data()); //compute F_ki(H(xi))

	for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
		for (u64 idxParty = 0; idxParty < aesKeys.size(); ++idxParty)
			inputSet2ZeroXOR[idxItem] = inputSet2ZeroXOR[idxItem] ^ ciphertexts[idxParty][idxItem];
}


inline void tpsi_test(u64 type_okvs, u64 type_security)
{
	std::cout << " ============== party_test ==============\n";

	u64 nParties = 7, setSize = 32, intersection_size = 2;
	u64 threshold = 4;
	u64 party_t_id = nParties - threshold - 1;

	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	std::vector <std::vector<block>> inputSets(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		inputSets[i].resize(setSize);
		for (u64 j = 0; j < setSize; ++j)
			inputSets[i][j] = prng.get<block>();
	}

	for (u64 i = 1; i < nParties; ++i) //same items
		for (u64 j = 0; j < intersection_size; ++j)
			inputSets[i][j] = inputSets[0][j];

	//generating aes keys
	std::vector<block> aesKeys(nParties); //aesKeys[0] for party 2
	for (u64 i = 0; i < aesKeys.size(); ++i)
		aesKeys[i] = prng.get<block>();

	std::vector <std::vector<block>> okvsTables(party_t_id);

	std::vector <std::vector<block>> inputSet2ZeroXOR(nParties); //but only use [t--->n]

	for (u64 idxParty = 0; idxParty < party_t_id; ++idxParty) //user computes XOR of all F(k, value) and encodes them before sending to party_t
	{
		user_encode(inputSets[idxParty], aesKeys, okvsTables[idxParty], party_t_id, nParties, type_okvs, type_security);
	}

	partyt_decode(inputSets[party_t_id], okvsTables, inputSet2ZeroXOR[party_t_id], type_okvs, type_security);

	for (u64 idxParty = party_t_id+1; idxParty < nParties; ++idxParty) //server
		server_prf(inputSets[idxParty], aesKeys, inputSet2ZeroXOR[idxParty], type_okvs, type_security);

	
	//check zeroXOR
	std::cout << " ============== check zeroXOR ==============\n";
	for (u64 i = 0; i < intersection_size*2; ++i)
	{
		block checkZeroXOR=ZeroBlock;
		for (u64 idxParty = party_t_id; idxParty < nParties; ++idxParty) //server
			checkZeroXOR = checkZeroXOR ^ inputSet2ZeroXOR[idxParty][i];
		if (i< intersection_size)
			std::cout <<  checkZeroXOR << " -----------expected 0 \n" ;
		else 
			std::cout << checkZeroXOR << " -----------expected !0 \n";
	}
	std::cout << " ============== done ==============\n";

}

inline void tpsi_party(u64 myIdx, u64 nParties, u64 setSize, u64 threshold, u64 type_okvs, u64 type_security)
{
	//party 0--->(t-1) distributes key + value to central parties 
	// party t computes all XOR F(k,value)
	// party t ---> n runs ZeroXOR

	u64 party_t_id = nParties - threshold-1; // party who computes XOR of all F(key, value) from users
	//u64 num_users = party_t - 1; //party who sends each key to P_{<n-t} and sends F(key, value) to P_{n-t}  


	std::fstream textout;
	textout.open("./runtime_" + myIdx, textout.app | textout.out);

#pragma region setup
	u64  psiSecParam = 40, bitSize = 128, numChannelThreads = 1, okvsTableSize = setSize;
	u64 party_n1 = nParties - 2, party_n = nParties - 1; //party n-1 vs n
	double dataSent, Mbps, MbpsRecv, dataRecv;
	Timer timer;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));
	u64 expected_intersection = 3;// (*(u64*)&prng.get<block>()) % setSize;


	if (type_okvs == GbfOkvs)
		okvsTableSize = 60 * setSize;
	else if (type_okvs == PolyOkvs)
		okvsTableSize = setSize;


	std::string name("psi");
	BtIOService ios(0);
	std::vector<BtEndpoint> ep(nParties);
	std::vector<std::vector<Channel*>> chls(nParties);

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


	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx) {
			chls[i].resize(numChannelThreads);
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j] = &ep[i].addChannel(name, name);
		}
	}

	u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;


	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	std::vector<block> inputSet(setSize);

	for (u64 i = 0; i < expected_intersection; ++i)
		inputSet[i] = prngSame.get<block>();

	for (u64 i = expected_intersection; i < setSize; ++i)
		inputSet[i] = prngDiff.get<block>();
#pragma endregion

	u64 num_threads = nParties - 1; //for party 1

	timer.reset();
	auto start = timer.setTimePoint("start");



	std::vector<block> aesSentKeys(nParties); // each users generates aes key. Indeed, we only use aesKeys[t->n]
	std::vector<block> aesReceivedKeys(party_t_id); // Indeed, we only use aesKeys[0->t-1]

	std::vector<block> inputSet2ZeroXOR(setSize); //for party n-1 and n


	//====================================
	//============sending and receiving aes keys========
	//Party $P_i$ for $i\in[1,v-1]$ chooses keys $\{k_i^j\}$ for $j\in[v+1,n]$ and sends $k_i^j$ to $P_j$
	if (myIdx < party_t_id) //user
	{
		for (u64 i = party_t_id+1; i < nParties; ++i)
		{
			aesSentKeys[i] = prng.get<block>(); //generating aes keys
			chls[i][0]->asyncSend(&aesSentKeys[i], sizeof(block)); //sending aesKeys[i] to party [t->n]
		
			std::cout << IoStream::lock;
			std::cout << aesSentKeys[i] << " - aesKeys[" << i << "] - myIdx" << myIdx << std::endl;
			std::cout << IoStream::unlock;
		}
	}

	else if (myIdx < nParties && myIdx >party_t_id) //server
	{
		for (u64 i = 0; i < party_t_id; ++i)
		{
			chls[i][0]->recv(&aesReceivedKeys[i], sizeof(block));  //party [t->n] receives aesKey from party [0->t-1]
			std::cout << IoStream::lock;
			std::cout << aesReceivedKeys[i] << " - aesReceivedKey[" <<i<<"] - myIdx" << myIdx << std::endl;
			std::cout << IoStream::unlock;
		}
	}

	//====================================
	//============compute encoding========


	/*std::cout << IoStream::lock;
	std::cout << inputSet[0] << " - inputSet - " << myIdx  << std::endl;
	std::cout << IoStream::unlock;*/

	if (myIdx < party_t_id) //user computes XOR of all F(k, value) and encodes them before sending to party_t
	{
		std::vector<block> okvsTable; //okvs of party1
		user_encode(inputSet, aesSentKeys, okvsTable, party_t_id, nParties, type_okvs, type_security);
		chls[party_t_id][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); //sending okvsTable to party_t

	/*	std::cout << IoStream::lock;
		for (u64 i = 0; i < okvsTable1.size(); i++)
			std::cout << okvsTable1[i] << " - " << i << "okvsTable1 party1_encode - " << myIdx << " ->" << party_n << std::endl;
		std::cout << IoStream::unlock;*/

	}
	
	else if (myIdx == party_t_id) //combined party
	{
		std::vector <std::vector<block>> okvsTables(party_t_id); //okvs of party 0->t
		for (u64 idxParty = 0; idxParty < party_t_id; idxParty++)
		{
			okvsTables[idxParty].resize(okvsTableSize);
			chls[idxParty][0]->recv(okvsTables[idxParty].data(), okvsTables[idxParty].size() * sizeof(block)); //receving okvsTable from party 0->t

			/*std::cout << IoStream::lock;
			for (u64 i = 0; i < 4; i++)
				std::cout << okvsTables[idxParty][i] << " - okvsTable party2_encode - " << myIdx << " <-" << idxParty + 1 << std::endl;
			std::cout << IoStream::unlock;*/
		}

		partyt_decode(inputSet, okvsTables, inputSet2ZeroXOR, type_okvs, type_security);

		std::cout << IoStream::lock;
		for (u64 i = 0; i < 2; i++)
			std::cout << inputSet2ZeroXOR[i] << " - inputSet2ZeroXOR-t " << myIdx << std::endl;
		std::cout << IoStream::unlock;
	}

	else if (myIdx < nParties && myIdx >party_t_id)  //server
	{
		std::vector<block> okvsTable; //okvs of each party 2 -> n-2
		server_prf(inputSet, aesReceivedKeys, inputSet2ZeroXOR, type_okvs, type_security);
	
		/*std::cout << IoStream::lock;
		for (u64 i = 0; i < 4; i++)
			std::cout << okvsTable[i] << " - okvsTable party2_encode: " << myIdx << " ->"<< party_n1 <<std::endl;
		std::cout << IoStream::unlock;*/

	}

	//====================================
	//============compute zeroXOR========

	if (myIdx < nParties && myIdx >= party_t_id) //for zeroXOR
	{
		
		if (myIdx == party_n) {
			/*Log::out << "mIntersection.size(): " << recv.mIntersection.size() << Log::endl;
			for (u64 i = 0; i < recv.mIntersection.size(); ++i)
			{
				std::cout << recv.mIntersection[i] << " - " << inputSet[recv.mIntersection[i]] << std::endl;

			}*/
		}
	}


	//close chanels 
	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j]->close();

	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			ep[i].stop();

	ios.stop();
}