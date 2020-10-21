#pragma once
#include "Crypto/PRNG.h"
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include <set>

using namespace osuCrypto;

inline void GbfEncode(const std::vector<std::pair<block, block>> key_values, std::vector<block>& garbledBF)
{
	u64 numHashFunctions = 40;
	std::vector<AES> mBFHasher(numHashFunctions);
	for (u64 i = 0; i < mBFHasher.size(); ++i)
		mBFHasher[i].setKey(_mm_set1_epi64x(i));

	u64 setSize = key_values.size();
	u64 mBfBitCount = 60 * setSize;
	garbledBF.resize(mBfBitCount);

	std::vector<std::set<u64>> idxs(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		u64 firstFreeIdx(-1);
		block sum = ZeroBlock;

		//std::cout << "input[" << i << "] " << inputs[i] << std::endl;

		//idxs.clear();
		for (u64 hashIdx = 0; hashIdx < mBFHasher.size(); ++hashIdx)
		{

			block hashOut = mBFHasher[hashIdx].ecbEncBlock(key_values[i].first);
			u64& idx = *(u64*)&hashOut;
			idx %= mBfBitCount;
			idxs[i].emplace(idx);

			//std::cout << idx << " ";
		}
		//std::cout << "\n";

		for (auto idx : idxs[i])
		{
			if (eq(garbledBF[idx], ZeroBlock))
			{
				if (firstFreeIdx == u64(-1))
				{
					firstFreeIdx = idx;
					//std::cout << "firstFreeIdx: " << firstFreeIdx << std::endl;

				}
				else
				{
					garbledBF[idx] = _mm_set_epi64x(idx, idx);
					//	std::cout << garbledBF[idx] <<"\n";
					sum = sum ^ garbledBF[idx];
					//std::cout << idx << " " << garbledBF[idx] << std::endl;
				}
			}
			else
			{
				sum = sum ^ garbledBF[idx];
				//std::cout << idx << " " << garbledBF[idx] << std::endl;
			}
		}

		garbledBF[firstFreeIdx] = sum ^ key_values[i].second;
		//std::cout << firstFreeIdx << " " << garbledBF[firstFreeIdx] << std::endl;
		//std::cout << test << "\n";
		//std::cout << "sender " << i << " *   " << garbledBF[firstFreeIdx] << "    " << firstFreeIdx << std::endl;
	}
}

inline  void GbfEncode(const std::vector<block> setKeys, const std::vector<block> setValues, std::vector<block>& garbledBF)
{
	std::vector<std::pair<block, block>> key_values(setKeys.size());

	for (u64 i = 0; i < key_values.size(); ++i)
	{
		memcpy((u8*)&key_values[i].first, (u8*)&setKeys[i], sizeof(block));
		memcpy((u8*)&key_values[i].second, (u8*)&setValues[i], sizeof(block));
	}
	std::cout << setValues[0] << " vs " << key_values[0].second << "\n";

	GbfEncode(key_values, garbledBF);
}

inline  void GbfDecode(const std::vector<block> garbledBF, const std::vector<block> setKeys, std::vector<block>& setValues)
{
	u64 numHashFunctions = 40;
	std::vector<AES> mBFHasher(numHashFunctions);
	for (u64 i = 0; i < mBFHasher.size(); ++i)
		mBFHasher[i].setKey(_mm_set1_epi64x(i));

	u64 setSize = setKeys.size();
	u64 mBfBitCount = 60 * setSize;
	setValues.resize(setSize);

	for (u64 i = 0; i < setSize; ++i)
	{
		//std::cout << "mSetY[" << i << "]= " << mSetY[i] << std::endl;
		//	std::cout << mSetX[i] << std::endl;

		std::set<u64> idxs;

		for (u64 hashIdx = 0; hashIdx < mBFHasher.size(); ++hashIdx)
		{
			block hashOut = mBFHasher[hashIdx].ecbEncBlock(setKeys[i]);
			u64& idx = *(u64*)&hashOut;
			idx %= mBfBitCount;
			idxs.emplace(idx);
		}

		setValues[i] = ZeroBlock;
		for (auto idx : idxs)
		{
			///std::cout << idx << " " << garbledBF[idx] << std::endl;
			setValues[i] = setValues[i] ^ garbledBF[idx];
		}

		//if (i == 0) //for test
		//	std::cout << mSetY[0] << "\t vs \t" << sum << std::endl;
	}

}

inline void GbfTest()
{
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	std::vector<std::pair<block, block>> key_values(128);
	std::vector<block> setKeys(128);
	std::vector<block> setValues(128);

	for (u64 i = 0; i < key_values.size(); ++i)
	{
		key_values[i].first = prng.get<block>();
		key_values[i].second = prng.get<block>();
		setKeys[i] = key_values[i].first;
		setValues[i] = key_values[i].second;
	}

	std::vector<block> garbledBF;
	//GbfEncode(key_values, garbledBF);
	GbfEncode(setKeys, setValues, garbledBF);
	GbfDecode(garbledBF, setKeys, setValues);

	std::cout << setValues[0] << " vs " << key_values[0].second << "\n";

}
