#pragma once
#include "Crypto/PRNG.h"
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/Log1.h"
#include <set>
#include "Hashing/polyFFT.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include <ObliviousDictionary.h>
#include "xxHash/xxhash.h"
#include <iostream>
#include <chrono>
#include <thread>

using namespace osuCrypto;


inline void GbfEncode(const std::vector<std::pair<block, block>> key_values, std::vector<block>& garbledBF)
{
    u64 setSize = key_values.size();
    u64 mBfBitCount = okvsLengthScale * setSize;
    u64 numHashFunctions = okvsHashFunctions;

    std::vector<AES> mBFHasher(numHashFunctions);
    for (u64 i = 0; i < mBFHasher.size(); ++i)
        mBFHasher[i].setKey(_mm_set1_epi64x(i));


    garbledBF.resize(mBfBitCount,ZeroBlock);
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


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
                    //	std::cout << coefficients[idx] <<"\n";
                    sum = sum ^ garbledBF[idx];
                    //std::cout << idx << " " << coefficients[idx] << std::endl;
                }
            }
            else
            {
                sum = sum ^ garbledBF[idx];
                //std::cout << idx << " " << coefficients[idx] << std::endl;
            }
        }

        if(firstFreeIdx!=-1)
            garbledBF[firstFreeIdx] = sum ^ key_values[i].second;
        //std::cout << firstFreeIdx << " " << coefficients[firstFreeIdx] << std::endl;
        //std::cout << test << "\n";
        //std::cout << "sender " << i << " *   " << coefficients[firstFreeIdx] << "    " << firstFreeIdx << std::endl;
    }

    //filling random for the rest
    for (u64 i = 0; i < garbledBF.size(); ++i)
        if (eq(garbledBF[i], ZeroBlock))
            garbledBF[i] = prng.get<block>();

    

    /*std::cout << IoStream::lock;
    for (u64 i = 0; i < 5; i++)
        std::cout << coefficients[i] << " - SimulatedOkvsEncode - " << i << std::endl;
    std::cout << IoStream::unlock;*/
}

inline  void GbfEncode(const std::vector<block> setKeys, const std::vector<block> setValues, std::vector<block>& garbledBF)
{
    std::vector<std::pair<block, block>> key_values(setKeys.size());

    for (u64 i = 0; i < key_values.size(); ++i)
    {
        memcpy((u8*)&key_values[i].first, (u8*)&setKeys[i], sizeof(block));
        memcpy((u8*)&key_values[i].second, (u8*)&setValues[i], sizeof(block));
    }
    //std::cout << setValues[0] << " vs " << key_values[0].second << "\n";

    GbfEncode(key_values, garbledBF);

    //simulat the cost of okvs
    if (setKeys.size() <= (1 << 12)) //set size =2^12
        this_thread::sleep_for(chrono::milliseconds(52));
    else if (setKeys.size() <= (1 << 16)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(103));
    else if (setKeys.size() <= (1 << 20)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(2838));
    else
        this_thread::sleep_for(chrono::milliseconds(2838*(setKeys.size()/(1<<20))));
}

inline  void GbfDecode(const std::vector<block> garbledBF, const std::vector<block> setKeys, std::vector<block>& setValues)
{
    u64 setSize = setKeys.size();
    u64 mBfBitCount = okvsLengthScale * setSize;
    u64 numHashFunctions = okvsHashFunctions;

    std::vector<AES> mBFHasher(numHashFunctions);
    for (u64 i = 0; i < mBFHasher.size(); ++i)
        mBFHasher[i].setKey(_mm_set1_epi64x(i));

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
            ///std::cout << idx << " " << coefficients[idx] << std::endl;
            setValues[i] = setValues[i] ^ garbledBF[idx];
        }

        //if (i == 0) //for test
        //	std::cout << mSetY[0] << "\t vs \t" << sum << std::endl;
    }

    //simulat the cost of okvs
    if (setKeys.size() <= (1 << 12)) //set size =2^12
        this_thread::sleep_for(chrono::milliseconds(3));
    else if (setKeys.size() <= (1 << 16)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(5));
    else if (setKeys.size() <= (1 << 20)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(990));
    else
        this_thread::sleep_for(chrono::milliseconds(990 * (setKeys.size() / (1 << 20))));
}

inline void GbfTest()
{
    std::cout << " ============== GbfTest ==============\n";

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    std::vector<std::pair<block, block>> key_values(128);
    std::vector<block> setKeys(128);
    std::vector<block> setValues(128);
    std::vector<block> setValuesOut(128);

    for (u64 i = 0; i < key_values.size(); ++i)
    {
        key_values[i].first = prng.get<block>();
        key_values[i].second = prng.get<block>();
        setKeys[i] = key_values[i].first;
        setValues[i] = key_values[i].second;
    }

    std::vector<block> garbledBF;
    //GbfEncode(key_values, coefficients);
    GbfEncode(setKeys, setValues, garbledBF);

    /*for (size_t i = 0; i < 10; i++)
        std::cout << garbledBF[i] << "\n";*/



    GbfDecode(garbledBF, setKeys, setValuesOut);

    for (size_t i = 0; i < 128; i++)
    {
        if(memcmp((u8*)&setValues[i], (u8*)&setValuesOut[i], sizeof(block)) == 1)
            std::cout << setValues[i] << " vs " << setValuesOut[i] << "\n";

    }
    std::cout << " ============== done ==============\n";

}


inline  void SimulatedOkvsEncode(const std::vector<block> setKeys, const std::vector<block> setValues, std::vector<block>& garbledBF)
{
     GbfEncode(setKeys, setValues, garbledBF); //using gbf with two hash function 

    //simulat the cost of okvs
    if (setKeys.size() <= (1 << 12)) //set size =2^12
        this_thread::sleep_for(chrono::milliseconds(52));
    else if (setKeys.size() <= (1 << 16)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(103));
    else if (setKeys.size() <= (1 << 20)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(2838));
    else
        this_thread::sleep_for(chrono::milliseconds(2838 * (setKeys.size() / (1 << 20))));
}

inline  void SimulatedOkvsDecode(const std::vector<block> garbledBF, const std::vector<block> setKeys, std::vector<block>& setValues)
{
    
    GbfDecode(garbledBF, setKeys, setValues);

    //simulat the cost of okvs
    if (setKeys.size() <= (1 << 12)) //set size =2^12
        this_thread::sleep_for(chrono::milliseconds(3));
    else if (setKeys.size() <= (1 << 16)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(5));
    else if (setKeys.size() <= (1 << 20)) //set size =2^16
        this_thread::sleep_for(chrono::milliseconds(990));
    else
        this_thread::sleep_for(chrono::milliseconds(990 * (setKeys.size() / (1 << 20))));
}


inline void PaxosEncode(const std::vector<block> setKeys, const std::vector<block> setValues, std::vector<block>& okvs, uint64_t fieldSize)
{
    int hashSize=setKeys.size(), gamma = 60, v=20;
    double c1 = 2.4;
    vector<uint64_t> keys;
//    vector<unsigned char> values;
    keys.resize(hashSize);
    int fieldSizeBytes = fieldSize % 8 == 0 ? fieldSize/8 : fieldSize/8 + 1;
    int zeroBits = 8 - fieldSize % 8;
//    values.resize(hashSize*fieldSizeBytes);
    ObliviousDictionary* dic = new OBD3Tables(hashSize, c1, fieldSize, gamma, v);
    dic->init();
    for (int i=0; i < setKeys.size(); i++){
        keys[i] = XXH64(&setKeys[i], 64, 0);
    }
    cout << "Done with keys" << endl;
    vector<byte> values;
    values.resize(setValues.size() * sizeof(block));
    memcpy(values.data(), setValues.data(), setValues.size() * sizeof(block));

    cout << "Copied vals" << endl;

    dic->setKeysAndVals(keys, values);
    dic->encode();

    vector<byte> x = dic->getVariables();
    memcpy(&okvs, x.data(), x.size());
    dic->checkOutput();
    cout << 'here' << endl;

}

inline  void PaxosDecode(const std::vector<block> paxosMat, const std::vector<block> setKeys, std::vector<block>& setValues)
{
    vector<byte> x(paxosMat.size()*sizeof(block));
    memcpy(x.data(), (byte*)&paxosMat, paxosMat.size());

    int hashSize = setKeys.size(), gamma = 60, v = 20, fieldSize = 128;
    double c1 = 2.4;
    vector<uint64_t> keys;
    //    vector<unsigned char> values;
    keys.resize(hashSize);
    int fieldSizeBytes = fieldSize % 8 == 0 ? fieldSize / 8 : fieldSize / 8 + 1;
    int zeroBits = 8 - fieldSize % 8;
    //    values.resize(hashSize*fieldSizeBytes);
    ObliviousDictionary* dic = new OBD3Tables(hashSize, c1, fieldSize, gamma, v);
    dic->init();

    for (int i = 0; i < setKeys.size(); i++) {
        keys[i] = XXH64(&setKeys[i], 64, 0);
        auto value = dic->decode(keys[i]);
        memcpy(&setValues, value.data(), sizeof(block));
    }
}


inline void PolyEncode(const std::vector<std::pair<block, block>> key_values, std::vector<block>& coefficents)
{
    ZZ_pX Polynomial;
    ZZ mPrime = to_ZZ("340282366920938463463374607431768211507"); //nextprime(2^128)
    ZZ_p::init(ZZ(mPrime));

    u64 degree = key_values.size() - 1; //2%
    coefficents.resize(degree + 1);

    ZZ_p* zzX = new ZZ_p[key_values.size()];
    ZZ_p* zzY = new ZZ_p[key_values.size()];
    ZZ zz;
    ZZ_pX* M = new ZZ_pX[degree * 2 + 1];;
    ZZ_p* a = new ZZ_p[degree + 1];;
    ZZ_pX* temp = new ZZ_pX[degree * 2 + 1];

    for (u64 idx = 0; idx < key_values.size(); idx++)
    {
        ZZFromBytes(zz, (u8*)&key_values[idx].first, sizeof(block));
        zzX[idx] = to_ZZ_p(zz);

        ZZFromBytes(zz, (u8*)&key_values[idx].second, sizeof(block));
        zzY[idx] = to_ZZ_p(zz);
    }
    prepareForInterpolate(zzX, degree, M, a, 1, mPrime);
    iterative_interpolate_zp(Polynomial, temp, zzY, a, M, degree * 2 + 1, 1, mPrime);

    for (int c = 0; c <= degree; c++) {
        BytesFromZZ((u8*)&coefficents[c], rep(Polynomial.rep[c]), sizeof(block));
    }

}

inline  void PolyEncode(const std::vector<block> setKeys, const std::vector<block> setValues, std::vector<block>& coefficents)
{
    std::vector<std::pair<block, block>> key_values(setKeys.size());

    for (u64 i = 0; i < key_values.size(); ++i)
    {
        memcpy((u8*)&key_values[i].first, (u8*)&setKeys[i], sizeof(block));
        memcpy((u8*)&key_values[i].second, (u8*)&setValues[i], sizeof(block));
    }
    //std::cout << setValues[0] << " vs " << key_values[0].second << "\n";

    PolyEncode(key_values, coefficents);
}

inline  void PolyDecode(const std::vector<block> coefficents, const std::vector<block> setKeys, std::vector<block>& setValues)
{
    setValues.resize(setKeys.size());
    ZZ_pX Polynomial;
    ZZ mPrime = to_ZZ("340282366920938463463374607431768211507"); //nextprime(2^128)
    ZZ_p::init(ZZ(mPrime));

    u64 degree = setKeys.size() - 1; //2%
    ZZ_p* zzX = new ZZ_p[setKeys.size()];
    ZZ_p* zzY = new ZZ_p[setKeys.size()];
    ZZ zz;

    for (u64 idx = 0; idx < setKeys.size(); idx++)
    {
        ZZFromBytes(zz, (u8*)&setKeys[idx], sizeof(block));
        zzX[idx] = to_ZZ_p(zz);
    }


    for (int c = 0; c <= degree; c++) {
        ZZFromBytes(zz, (u8*)&coefficents[c], sizeof(block));
        NTL::SetCoeff(Polynomial, c, to_ZZ_p(zz));
    }

    multipoint_evaluate_zp(Polynomial, zzX,zzY, degree, 1, mPrime);

    for (u64 idx = 0; idx < setKeys.size(); idx++)
        BytesFromZZ((u8*)&setValues[idx], rep(zzY[idx]), sizeof(block));
}

inline void PolyTest()
{
    std::cout << " ============== GbfTest ==============\n";

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    std::vector<std::pair<block, block>> key_values(128);
    std::vector<block> setKeys(128);
    std::vector<block> setValues(128);
    std::vector<block> setValuesOut(128);

    for (u64 i = 0; i < key_values.size(); ++i)
    {
        key_values[i].first = prng.get<block>();
        key_values[i].second = prng.get<block>();
        setKeys[i] = key_values[i].first;
        setValues[i] = key_values[i].second;
    }

    std::vector<block> coefficients;
    //SimulatedOkvsEncode(key_values, coefficients);
    PolyEncode(setKeys, setValues, coefficients);

    /*for (size_t i = 0; i < 10; i++)
        std::cout << coefficients[i] << "\n";*/



    PolyDecode(coefficients, setKeys, setValuesOut);

    for (size_t i = 0; i < 128; i++)
    {
        //if (setValues[i] != setValuesOut[i])
        if (memcmp((u8*)&setValues[i], (u8*)&setValuesOut[i], sizeof(block)) == 1)
            std::cout << setValues[i] << " vs " << setValuesOut[i] << "\n";

    }
    std::cout << " ============== done ==============\n";

}
