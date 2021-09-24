//
// Created by moriya on 7/17/19.
//

#ifndef BENNYPROJECT_OBLIVIOUSDICTIONARY_H
#define BENNYPROJECT_OBLIVIOUSDICTIONARY_H

#include <unordered_set>
#include <unordered_map>
//#include <libscapi/include/primitives/Prg.hpp>
//#include <libscapi/include/comm/MPCCommunication.hpp>
#include "Hasher.h"
#include <NTL/mat_GF2E.h>
#include <NTL/GF2E.h>
#include <NTL/GF2X.h>
#include <NTL/GF2XFactoring.h>
#include "gf2e_mat_solve.h"
#include "Crypto/PRNG.h"

#include <chrono>
#include <queue>
#include <fstream>
typedef unsigned char byte;

using namespace std::chrono;

using namespace std;
using namespace NTL;


class ObliviousDictionary {
protected:

    int hashSize;
    int fieldSize, fieldSizeBytes;
    int gamma, v;

//    PrgFromOpenSSLAES prg;
    vector<uint64_t> keys;
    vector<byte> values;

    unordered_map<uint64_t, GF2E> vals;
//    vector<vector<uint64_t>> indices;

    int reportStatistics=0;
    ofstream statisticsFile;

    GF2EVector variables;
    vector<byte> sigma;


public:

    ObliviousDictionary(int hashSize, int fieldSize, int gamma, int v);

     ~ObliviousDictionary(){
         if (reportStatistics == 1) {

             statisticsFile.close();
         }
    }


    virtual void setKeysAndVals(vector<uint64_t>& keys, vector<byte>& values){

         this->keys = keys;
         this->values = values;

         vals.clear();
         vals.reserve(hashSize);
         GF2X temp;
         for (int i=0; i < hashSize; i++){

//        for (int j=0; j<fieldSizeBytes; j++){
//            cout<<"val in bytes = "<<(int)(values[i*fieldSizeBytes + j]) << " ";
//        }
//        cout<<endl;

             GF2XFromBytes(temp, values.data() + i*fieldSizeBytes ,fieldSizeBytes);
             vals.insert({keys[i], to_GF2E(temp)});
//        auto tempval = to_GF2E(temp);
//        cout<<"val in GF2E = "<<tempval<<endl;

//        vector<byte> tempvec(fieldSizeBytes);
//        BytesFromGF2X(tempvec.data(), rep(tempval), fieldSizeBytes);
//        for (int j=0; j<fieldSizeBytes; j++){
//            cout<<"returned val in bytes = "<<(int)*(tempvec.data() + j)<< " ";
//        }
//        cout<<endl;
         }
//        for (int i=0; i<hashSize; i++){
//            cout << "key = " << keys[i] << " val = ";
//
//            for (int j=0; j<fieldSizeBytes; j++){
//                cout<<(int)(values[i*fieldSizeBytes + j])<<" ";
//            }
//            cout<<endl;
//        }
     }

    virtual void init() = 0;

    virtual vector<uint64_t> dec(uint64_t key) = 0;
    virtual vector<uint64_t> decOptimized(uint64_t key) = 0;

    virtual vector<byte> decode(uint64_t key) = 0;

    virtual bool encode() = 0;

    void generateRandomEncoding() {
        cout<<"variables.size() = "<<variables.size()<<endl;
        cout<<"fieldSizeBytes = "<<fieldSizeBytes<<endl;

        sigma.resize(variables.size()*fieldSizeBytes);
//        sigma.insert(0);
//        prg.getPRGBytes(sigma, 0, sigma.size());
        int zeroBits = 8 - fieldSize % 8;
        for (int i=0; i<variables.size(); i++){
//        cout << "key = " << keys[i] << " val = ";
//        for (int j=0; j<fieldSizeBytes; j++){
//            cout<<(int)(vals[i*fieldSizeBytes + j])<<" " << std::bitset<8>(vals[i*fieldSizeBytes + j]) << " ";
//        }
//        cout<<endl;

            sigma[(i+1)*fieldSizeBytes-1] = sigma[(i+1)*fieldSizeBytes-1]  >> zeroBits;
//
//        cout << "key = " << keys[i] << " val = ";
//        for (int j=0; j<fieldSizeBytes; j++){
//            cout<<(int)(vals[i*fieldSizeBytes + j])<<" " << std::bitset<8>(vals[i*fieldSizeBytes + j]) << " ";
//        }
//        cout<<endl;
        }
        GF2X temp;
//        vector<byte> temp1(fieldSizeBytes);
        for (int i=0; i < variables.size(); i++){

            GF2XFromBytes(temp, sigma.data() + i*fieldSizeBytes ,fieldSizeBytes);
            variables[i] = to_GF2E(temp);

//            BytesFromGF2X(temp1.data(), rep(variables[i]), fieldSizeBytes);
//
//            for (int j=0; j<fieldSizeBytes; j++){
//                if (temp1[j] != sigma[i*fieldSizeBytes + j])
//                    cout<<"error!! sigma[i*fieldSizeBytes + j] = "<<(int)sigma[i*fieldSizeBytes + j]<<" temp1[j] = "<<(int)temp1[j]<<endl;
//                //            for (int j=0; j<fieldSizeBytes; j++){
//                //                cout<<(int)*(sigma.data() + i*fieldSizeBytes + j)<< " ";
//                //            }
//                //            cout<<endl;
//            }
//        auto tempval = to_GF2E(temp);
//        cout<<"val in GF2E = "<<tempval<<endl;

//        vector<byte> tempvec(fieldSizeBytes);
//        BytesFromGF2X(tempvec.data(), rep(tempval), fieldSizeBytes);
//        for (int j=0; j<fieldSizeBytes; j++){
//            cout<<"returned val in bytes = "<<(int)*(tempvec.data() + j)<< " ";
//        }
//        cout<<endl;
        }

    }

    void setReportStatstics(int flag){
        reportStatistics = flag;
        if (reportStatistics == 1) {

            cout<<"statistics file created"<<endl;
            statisticsFile.open("statistics.csv");
            statisticsFile << "-------------Statistics-----------.\n";
        }};

    virtual vector<byte> getVariables() {

        if (sigma.size() == 0) { //If the variables do not randomly chosen
            sigma.resize(variables.size() * fieldSizeBytes);
            for (int i = 0; i < variables.size(); i++) {
                //            cout<<"variables["<<i<<"] = "<<variables[i]<<endl;
                BytesFromGF2X(sigma.data() + i * fieldSizeBytes, rep(variables[i]), fieldSizeBytes);
                //            for (int j=0; j<fieldSizeBytes; j++){
                //                cout<<(int)*(sigma.data() + i*fieldSizeBytes + j)<< " ";
                //            }
                //            cout<<endl;
            }
//        } else {
//            cout<<"variables.size() = "<<variables.size()<<endl;
//            vector< byte> temp(variables.size() * fieldSizeBytes);
//            for (int i = 0; i < variables.size(); i++) {
//                            cout<<"variables["<<i<<"] = "<<variables[i]<<endl;
//                BytesFromGF2X(temp.data() + i * fieldSizeBytes, rep(variables[i]), fieldSizeBytes);
//                            for (int j=0; j<fieldSizeBytes; j++){
//                                cout<<(int)*(temp.data() + i*fieldSizeBytes + j)<< " ";
//                            }
//                            cout<<endl;
//            }
//            bool error = false;
//            for (int i=0; i<sigma.size(); i++){
//                if (sigma[i] != temp[i]){
//                    error = true;
////                    cout<<"sigma[i] = "<<(int)sigma[i]<<" temp[i] = "<<(int)temp[i]<<endl;
//                }
//            }
//            if (error)
//                cout<<"values have been changed!"<<endl;
        }

        return sigma;
    }

    virtual bool checkOutput() = 0;

    int getHashSize(){return hashSize;}
    virtual int getTableSize() = 0;
    int getGamma() {return gamma; }

};

class OBDTables : public ObliviousDictionary{
protected:

    int tableRealSize;

    uint64_t dhSeed;
    double c1;

    vector<uint64_t> peelingVector;
    int peelingCounter;

    Hasher DH;

    vector<byte> sign;

    uint64_t getDHBits(uint64_t key);

public:

    OBDTables(int hashSize, double c1, int fieldSize, int gamma, int v) : ObliviousDictionary(hashSize, fieldSize, gamma, v), c1(c1){
        //the value is fixed for tests reasons
        dhSeed = 5;
        DH = Hasher(dhSeed);

//        prg = PrgFromOpenSSLAES(hashSize*fieldSizeBytes*4);
//        auto key = prg.generateKey(128);
//        prg.setKey(key);
    }

    void init() override;

    virtual void createSets() = 0;

    bool encode() override;

    virtual void fillTables() = 0;

    virtual int peeling() = 0;

    virtual void generateExternalToolValues() = 0;

    virtual void unpeeling() = 0;

    virtual bool hasLoop() = 0;

};

class OBD2Tables : public OBDTables{

private:
    uint64_t firstSeed, secondSeed;
    unordered_set<uint64_t, Hasher> first;
    unordered_set<uint64_t, Hasher> second;

public:
    OBD2Tables(int hashSize, double c1, int fieldSize, int gamma, int v);

    void createSets() override;

    void init() override;

    vector<uint64_t> dec(uint64_t key) override;
    vector<uint64_t> decOptimized(uint64_t key) override;

    vector<byte> decode(uint64_t key) override;

    void fillTables() override;

    int peeling() override;

    void generateExternalToolValues() override;

    void unpeeling() override;

    bool checkOutput() override;

    bool hasLoop() override;

    int getTableSize() override {return 2*tableRealSize + gamma;}
};

class OBD3Tables : public OBDTables {
private:
    uint64_t firstSeed, secondSeed, thirdSeed;
    unordered_set<uint64_t, Hasher> first;
    unordered_set<uint64_t, Hasher> second;
    unordered_set<uint64_t, Hasher> third;


    void handleQueue(queue<int> &queueMain, unordered_set<uint64_t, Hasher> &main,
                     queue<int> &queueOther1, unordered_set<uint64_t, Hasher> &other1,
                     queue<int> &queueOther2,unordered_set<uint64_t, Hasher> &other2);

public:

    OBD3Tables(int hashSize, double c1, int fieldSize, int gamma, int v);

    void createSets() override;

    void init() override;

    vector<uint64_t> dec(uint64_t key) override;

    vector<uint64_t> decOptimized(uint64_t key) override;

    vector<byte> decode(uint64_t key) override;

    void fillTables() override;

    int peeling() override;

    void generateExternalToolValues() override;

    void unpeeling() override;

    bool checkOutput() override;

    bool hasLoop() override;

    int getTableSize() override {return 3*tableRealSize + gamma;}


};

class StarDictionary : public ObliviousDictionary {
private:
    vector<OBD3Tables*> bins;
    vector<vector<uint64_t>> keysForBins;
    vector<vector<byte>> valsForBins;

    int q;

    Hasher hashForBins;
    int numItemsForBin;
    int center;
    int numThreads = 1;

    void peelMultipleBinsThread(int start, int end, vector<int> &failureIndices, int threadId);

    void unpeelMultipleBinsThread(int start, int end, int failureIndex);

    void setNewValsThread(int start, int end, int failureIndex);

public:

    StarDictionary(int numItems, double c1, double c2, int q, int fieldSize, int gamma, int v, int numThreads = 1);

    void setKeysAndVals(vector<uint64_t>& keys, vector<byte>& values) override;

    void init() override;

    vector<uint64_t> dec(uint64_t key) override;

    vector<uint64_t> decOptimized(uint64_t key) override;

    vector<byte> decode(uint64_t key);

    bool encode() override;

    bool checkOutput() override;

    int getTableSize() override {
        return (q+1)*(bins[0]->getTableSize());
    }

    vector<byte> getVariables() override;

    bool checkOutput(uint64_t key, int valIndex);
};




#endif //BENNYPROJECT_OBLIVIOUSDICTIONARY_H
