//
// Created by moriya on 7/17/19.
//

#include <cstring>
#include <thread>
#include "ObliviousDictionary.h"

ObliviousDictionary::ObliviousDictionary(int hashSize, int fieldSize, int gamma, int v) : hashSize(hashSize), fieldSize(fieldSize), gamma(gamma), v(v){

    initField(fieldSize);
    fieldSizeBytes = fieldSize % 8 == 0 ? fieldSize/8 : fieldSize/8 + 1;

//    auto key = prg.generateKey(128);
//    prg.setKey(key);


//indices.resize(hashSize);

//    firstEncValues.resize(tableRealSize, 0);
//    secondEncValues.resize(tableRealSize, 0);

//    keys.resize(hashSize);
//    vals.reserve(hashSize);
//
//    for (int i=0; i<hashSize; i++){
//        keys[i] = prg.getRandom64() >> 3;
//        vals.insert({keys[i],prg.getRandom64()>>3});
//    }
//
//    int numKeysToCheck = 10;
//    cout<<"keys to check with the other party"<<endl;
//    for (int i=0; i<numKeysToCheck; i++){
//        cout<<"key = "<<keys[i]<<" val = "<<vals[keys[i]]<<endl;
//    }

}

uint64_t OBDTables::getDHBits(uint64_t key){
    auto bits = DH(key);
    return bits >> (64-gamma);
}

void OBDTables::init() {

    peelingVector.clear();
    peelingCounter = 0;
}

bool OBDTables::encode(){
    auto start = high_resolution_clock::now();
    auto t1 = high_resolution_clock::now();

    fillTables();
    auto t2 = high_resolution_clock::now();

    auto duration = duration_cast<milliseconds>(t2-t1).count();
    cout << "fillTables took in milliseconds: " << duration << endl;

    t1 = high_resolution_clock::now();
    auto res = peeling();

    t2 = high_resolution_clock::now();

    duration = duration_cast<milliseconds>(t2-t1).count();
    cout << "peeling took in milliseconds: " << duration << endl;

    t1 = high_resolution_clock::now();
    generateExternalToolValues();
    t2 = high_resolution_clock::now();

    duration = duration_cast<milliseconds>(t2-t1).count();
    cout << "calc equations took in milliseconds: " << duration << endl;

    t1 = high_resolution_clock::now();
    unpeeling();

    t2 = high_resolution_clock::now();

    duration = duration_cast<milliseconds>(t2 - t1).count();
    cout << "unpeeling took in milliseconds: " << duration << endl;

    auto end = high_resolution_clock::now();

    duration = duration_cast<milliseconds>(end - start).count();
    cout << "encode took in milliseconds: " << duration << endl;
    return res;
};

OBD2Tables::OBD2Tables(int hashSize, double c1, int fieldSize, int gamma, int v) : OBDTables(hashSize, c1, fieldSize, gamma, v){
    //the values are fixed for tests reasons
    firstSeed = 1;
    secondSeed = 2;


    auto start = high_resolution_clock::now();
    createSets();
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end-start).count();

    cout << "time in milliseconds for create sets: " << duration << endl;
    variables.resize(2*tableRealSize + gamma, to_GF2E(0));
    sign.resize(2*tableRealSize, 0);

}

void OBD2Tables::createSets(){
    double factorSize = c1/2;
    first = unordered_set<uint64_t, Hasher>(hashSize*factorSize, Hasher(firstSeed));
    second = unordered_set<uint64_t, Hasher>(hashSize*factorSize, Hasher(secondSeed));

    tableRealSize = first.bucket_count();
    cout<<"tableRealSize = "<<tableRealSize<<endl;

//    while(tableRealSize/1.2 < hashSize){
//        first = unordered_set<uint64_t, Hasher>(tableRealSize + 1, Hasher(firstSeed));
//        second = unordered_set<uint64_t, Hasher>(tableRealSize + 1, Hasher(secondSeed));
//
//        tableRealSize = first.bucket_count();
//        cout<<"tableRealSize = "<<tableRealSize<<endl;
//    }

//    hashSize = tableRealSize/1.2;
}

void OBD2Tables::init() {

    OBDTables::init();
    first.clear();
    second.clear();
}

vector<uint64_t> OBD2Tables::dec(uint64_t key){
//    auto keyIndices = indices[key];
//    if(keyIndices.size() == 0) {
//        cout<<"first time"<<endl;
    vector<uint64_t> keyIndices;
    keyIndices.push_back(first.bucket(key));
    keyIndices.push_back(tableRealSize + second.bucket(key));

    auto dhBits = getDHBits(key);
    uint64_t mask = 1;
    for (int j = 0; j < gamma; j++) {
        if ((dhBits & mask) == 1) {
            keyIndices.push_back(2 * tableRealSize + j); //put 1 in the right vertex of the edge
        }
        dhBits = dhBits >> 1;
    }
//        indices[key] = move(keyIndices);

//    }

    return keyIndices;
}

vector<uint64_t> OBD2Tables::decOptimized(uint64_t key){
//    auto keyIndices = indices[key];
//    if(keyIndices.size() == 0) {
//        cout<<"first time"<<endl;
    vector<uint64_t> keyIndices(10);
    keyIndices[0] = first.bucket(key);
    keyIndices[1] = tableRealSize + second.bucket(key);

    auto dhBits = getDHBits(key);
    byte* dhBytes = (byte*) (&dhBits);
    for (int j = 0; j < 8; j++) {
        keyIndices[2 + j] = dhBytes[j]; //put 1 in the right vertex of the edge
    }
//        indices[key] = move(keyIndices);

//    }

    return keyIndices;
}

vector<byte> OBD2Tables::decode(uint64_t key){
    auto indices = dec(key);

    GF2E val(0);
    for (int j=0; j<indices.size(); j++){
        val += variables[indices[j]]; //put 1 in the right vertex of the edge

    }
    vector<byte> valBytes(fieldSizeBytes);
    BytesFromGF2X(valBytes.data(), rep(val), fieldSizeBytes);

    return valBytes;
}

void OBD2Tables::fillTables(){

    for (int i=0; i<hashSize; i++){

//            cout<<"key is "<<keys[i]<<endl;
//        auto pair = first.insert(keys[i]);
        first.insert(keys[i]);
        second.insert(keys[i]);

//        if (pair.second == false){
//            cout<<"key = "<<keys[i]<<" i = "<<i<<endl;
//        }
    }

}

int OBD2Tables::peeling(){

    peelingVector.resize(hashSize);
    peelingCounter = 0;

    auto t1 = high_resolution_clock::now();
    //Goes on the first hash
    for (int position = 0; position<tableRealSize; position++){
        if (first.bucket_size(position) == 1){
            //Delete the vertex from the graph
            auto key = *first.begin(position);
//                cout<<"remove key "<<key<<endl;
            peelingVector[peelingCounter++] = key;
            first.erase(key);

            //Update the second vertex on the edge
            second.erase(key);
        }
    }
    auto t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t2-t1).count();

    cout << "time in milliseconds for first loop: " << duration << endl;

    t1 = high_resolution_clock::now();
    //goes on the second hash
    for (int position = 0; position<tableRealSize; position++){
        if (second.bucket_size(position) == 1){
            //Delete the vertex from the graph
            auto key = *second.begin(position);
//                peelingVector.push_back(key);
//                cout<<"remove key "<<key<<endl;
//                second.erase(key);

            int secondBucket = 0;

            while(secondBucket <= position) {

                peelingVector[peelingCounter++] = key;
//                    cout<<"remove key "<<key<<endl;
                second.erase(key);

//                    if (secondBucket>0) cout<<"loop in peeling"<<endl;
                //Update the second vertex on the edge
                int bucket = first.bucket(key);
                first.erase(key);
                if (first.bucket_size(bucket) == 1) {
                    key = *first.begin(bucket);
//                        cout<<"remove key from first "<<key<<endl;
                    peelingVector[peelingCounter++] = key;
                    first.erase(key);

                    //Update the second vertex on the edge
                    secondBucket = second.bucket(key);
                    second.erase(key);
                    if (second.bucket_size(secondBucket) == 1) {
                        key = *second.begin(secondBucket);
//                            peelingVector.push_back(key);
//                            cout<<"remove key "<<key<<endl;
//                            second.erase(key);
                    } else {
                        secondBucket = position + 1;
                    }
                } else {
                    secondBucket = position + 1;
                }

            }
        }
    }
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2-t1).count();

    cout << "time in milliseconds for second loop: " << duration << endl;

    if (hasLoop()){
        cout << "remain loops!!!" << endl;
    }

    cout<<"peelingCounter = "<<peelingCounter<<endl;

    if (hashSize - peelingCounter > v){
        return 0; //Failure
    }
    else return 1;

}

void OBD2Tables::generateExternalToolValues(){

//    int matrixSize = first.size()*(2*tableRealSize+gamma); // the rows count is the number of edges left after peeling
    //columns count is number of vertexes and gamma bits.

    auto start = high_resolution_clock::now();
    int matrixSize = hashSize - peelingCounter;
    GF2EMatrix matrix(matrixSize);

    cout<<"num of rows = "<<matrixSize<<endl;
    cout<<"num of cols = "<<2*matrixSize + gamma<<endl;
//    for(size_t i = 0; i < matrixSize; ++i) {
//        matrix[i].resize(2*tableRealSize+gamma);
//        for(size_t j = 0; j < 2*tableRealSize+gamma; ++j) {
//            matrix[i][j] = to_GF2E(0);
//        }
//    }
    GF2EVector values(matrixSize);

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end-start).count();

    cout << "construct time in milliseconds for protocol: " << duration << endl;

    unordered_map<uint64_t, int> firstTableCols;
    unordered_map<uint64_t, int> secondTableCols;
//    cout<<"matrix:"<<endl;
//    for (int i=0; i<first.size(); i++){
//        for (int j=0; j<2*tableRealSize+gamma; j++){
//            cout<<matrix[i][j]<<" ";
//        }
//        cout<<endl;
//    }
    //Get all the edges that are in the graph's circles and calc the polynomial values that should be for them.

    start = high_resolution_clock::now();
    int rowCounter = 0;
    int firstColsCounter = 0;
    int secondColsCounter = 0;

    int firstPos, secondPos;
    for (int i=0; i<tableRealSize; i++){
        if (first.bucket_size(i) > 1){
            for (auto key = first.begin(i); key!= first.end(i); ++key){

                matrix[rowCounter].resize(2*matrixSize+gamma);

                if (firstTableCols.find(i) == firstTableCols.end()){
                    firstTableCols.insert({i, firstColsCounter});
                    firstColsCounter++;
                }

                int secondIndex = second.bucket(*key);
                if (secondTableCols.find(secondIndex) == secondTableCols.end()){
                    secondTableCols.insert({secondIndex, secondColsCounter});
                    secondColsCounter++;

                }
                firstPos = firstTableCols[i];
                secondPos = secondTableCols[secondIndex];
//                cout<<"key "<<*key<<" first hash val = "<<i<< "and index "<<firstTableCols[i]<<" in the first cols"<<endl;
//                cout<<"key "<<*key<<" second hash val = "<<secondIndex<<"and index "<<secondTableCols[secondIndex]<<" in the second cols"<<endl;


                matrix[rowCounter][firstPos] = to_GF2E(1); //put 1 in the left vertex of the edge
                matrix[rowCounter][matrixSize + secondPos] = to_GF2E(1); //put 1 in the right vertex of the edge
                sign[i] = 1;
                sign[tableRealSize + secondIndex] = 1;
                auto dhBits = getDHBits(*key);
//                cout<<"DH bits: "<<dhBits<<endl;
                uint64_t mask = 1;
                for (int j=0; j<gamma; j++){
//                    cout<<(dhBits & mask)<<" ";
                    matrix[rowCounter][ 2*matrixSize + j] = to_GF2E(dhBits & mask); //put 1 in the right vertex of the edge
                    dhBits = dhBits >> 1;

                }
//                cout<<endl;
                values[rowCounter] = vals[*key];
                rowCounter++;

            }
        }
    }

    end = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(end-start).count();

    cout << "fill time in milliseconds for protocol: " << duration << endl;

//    cout<<"matrix:"<<endl;
//    for (int i=0; i<rowCounter; i++){
//        for (int j=0; j<2*rowCounter+gamma; j++){
//            cout<<matrix[i][j]<<" ";
//        }
//        cout<<endl;
//    }

    cout<<"num of equations =  "<<rowCounter<<endl;

    if(reportStatistics==1) {

        statisticsFile << rowCounter << ", \n";
    }

    start = high_resolution_clock::now();

    GF2EVector variablesSlim(2*matrixSize + gamma);
    //TODO call the solver and get the results in variables
    solve_api(matrix, values, variablesSlim, fieldSize);

    end = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(end-start).count();

    cout << "solver time in milliseconds for protocol: " << duration << endl;
    for (int i=0; i<tableRealSize; i++) {
        if (first.bucket_size(i) > 1) {
            for (auto key = first.begin(i); key != first.end(i); ++key) {
//                matrix[edgesCounter*(2*tableRealSize+60) + i] = 1; //put 1 in the left vertex of the edge
//                matrix[edgesCounter*(2*tableRealSize+60) + tableRealSize + second.bucket(*key)] = 1; //put 1 in the right vertex of the edge

                int secondIndex = second.bucket(*key);
                variables[i] = variablesSlim[firstTableCols[i]];
                variables[tableRealSize + secondIndex] = variablesSlim[matrixSize + secondTableCols[secondIndex]];
//                auto val = variables[i] + variables[tableRealSize + second.bucket(*key)] ;
//                auto dhBits = getDHBits(*key);
//                uint64_t mask = 1;
//                for (int j=0; j<gamma; j++){
////                    matrix[edgesCounter*(2*tableRealSize+60) + 2*tableRealSize + j] = dhBIts & mask; //put 1 in the right vertex of the edge
//                    if (dhBits & mask)
//                        val +=variables[ 2*tableRealSize + j];
//                    dhBits = dhBits >> 1;
//
//                }
//
//                if (val != vals[*key]){
//                    cout<<"wrong value!!"<<endl;
//                } else{
//                    cout<<"correct!!"<<endl;
//                }
//                edgesCounter++;

            }
        }
    }

    for (int i=0; i<gamma; i++){
        variables[2*tableRealSize + i] = variablesSlim[2*matrixSize + i];
    }


//    cout<<"variables:"<<endl;
//    for (int i=0; i<variables.size(); i++){
//        cout<<"variable["<<i<<"] = "<<variables[i]<<endl;
//    }

}




void OBD2Tables::unpeeling(){
    cout<<"in unpeeling"<<endl;
    uint64_t key;
    byte* randomVal;
    GF2E dhBitsVal;
    GF2X temp;

//    vector<uint64_t> polyVals(peelingCounter);
//    Poly::evalMersenneMultipoint(polyVals, polynomial, peelingVector);

    while (peelingCounter > 0){
//            cout<<"key = "<<key<<endl;
        key = peelingVector[--peelingCounter];
        auto indices = dec(key);
//cout<<"indices = "<<endl;
//for (int i=0; i<indices.size(); i++){
//    cout<<indices[i]<<" ";
//}
//cout<<endl;
        dhBitsVal = 0;
        for (int j=2; j<indices.size(); j++){
//            if (variables[2*tableRealSize+ indices[j]] == 0){
//                randomVal = prg.getRandom64()  >> 3;
//                GF2XFromBytes(temp, (byte*)&randomVal ,8);
//                variables[2*tableRealSize+ indices[j]] = to_GF2E(temp);
//            }
            dhBitsVal += variables[indices[j]]; //put 1 in the right vertex of the edge

//            cout<<"variable in "<<indices[j]<<" place = "<<variables[2*tableRealSize+ indices[j]]<<endl;
        }
//        Poly::evalMersenne((ZpMersenneLongElement*)&poliVal, polynomial, (ZpMersenneLongElement*)&key);
//        poliVal = polyVals[peelingCounter];
        if (variables[indices[0]] == 0 && variables[indices[1]] == 0 && sign[indices[0]] == 0 && sign[indices[1]] == 0){
//            randomVal = prg.getPRGBytesEX(fieldSizeBytes);
//            randomVal = 0;
            vector<byte> r;
            r.resize(fieldSizeBytes);
            GF2XFromBytes(temp, (unsigned char *)&r ,fieldSizeBytes);
            variables[indices[0]] = to_GF2E(temp);
//                cout<<"set RANDOM value "<<variables[indices[0]]<<" in index "<<indices[0]<<endl;
        }
        if (variables[indices[0]] == 0 && sign[indices[0]] == 0){
            variables[indices[0]] = vals[key] + variables[indices[1]] + dhBitsVal;
//                cout<<"set value "<<variables[indices[0]]<<" in index "<<indices[0]<<endl;
//            cout<<"variables["<<indices[0]<<"] = "<<variables[indices[0]]<<endl;
//            cout<<"variables["<<tableRealSize + indices[1]<<"] = "<<variables[tableRealSize + indices[1]]<<endl;
//            cout<<"dhBitsVal = "<<dhBitsVal<<endl;
//            cout<<"val = "<<vals[key]<<endl;
        } if (variables[indices[1]] == 0 && sign[indices[1]] == 0){
            variables[indices[1]] = vals[key] + variables[indices[0]] + dhBitsVal;
//                cout<<"set value "<<variables[tableRealSize + indices[1]]<<" index "<<tableRealSize + indices[1]<<endl;
//            cout<<"variables["<<indices[0]<<"] = "<<variables[indices[0]]<<endl;
//            cout<<"variables["<<tableRealSize + indices[1]<<"] = "<<variables[tableRealSize + indices[1]]<<endl;
//            cout<<"dhBitsVal = "<<dhBitsVal<<endl;
//            cout<<"val = "<<vals[key]<<endl;
        }
    }
//    cout<<"peelingCounter = "<<peelingCounter<<endl;

//    cout<<"variables:"<<endl;
//    for (int i=0; i<variables.size(); i++){
//        cout<<"variable["<<i<<"] = "<<variables[i]<<" ";
//    }
//    cout<<endl;
}

bool OBD2Tables::checkOutput(){

    uint64_t key;
    GF2E val, dhBitsVal;
    bool error = false;

    for (int i=0; i<hashSize; i++){
        key = keys[i];
        val = vals[key];

        auto indices = dec(key);

        dhBitsVal = 0;
        for (int j=2; j<indices.size(); j++){
            dhBitsVal += variables[indices[j]]; //put 1 in the right vertex of the edge

        }

        if ((variables[indices[0]] + variables[indices[1]] + dhBitsVal) == val) {
//            if (i%100000 == 0)
//                cout<<"good value!!! val = "<<val<<endl;
        } else {//if (!hasLoop()){
            error = true;
            cout<<"invalid value :( val = "<<val<<" wrong val = "<<(variables[indices[0]] + variables[indices[1]] + dhBitsVal)<<endl;
            cout<<"variables["<<indices[0]<<"] = "<<variables[indices[0]]<<endl;
            cout<<"variables["<<indices[1]<<"] = "<<variables[indices[1]]<<endl;
            cout<<"dhBitsVal = "<<dhBitsVal<<endl;
        }

    }
    if (!error){
        cout<<"success!!!! dictionary is fine."<<endl;
    }
    return error;
}

bool OBD2Tables::hasLoop(){
    for (int position = 0; position<tableRealSize; position++) {
        if (first.bucket_size(position) > 1) {
            return true;
        }
    }
    return false;
}

OBD3Tables::OBD3Tables(int hashSize, double c1, int fieldSize, int gamma, int v) : OBDTables(hashSize, c1, fieldSize, gamma, v){

    firstSeed = 1;
    secondSeed = 2;
    thirdSeed = 3;

    auto start = high_resolution_clock::now();
    createSets();
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end-start).count();

//    cout << "time in milliseconds for create sets: " << duration << endl;
//
//

    variables.resize(3*tableRealSize + gamma, to_GF2E(0));
    sign.resize(3*tableRealSize, 0);

}



void OBD3Tables::createSets(){
    double factorSize = c1/3;
//    cout<<"factorSize = "<<factorSize<<endl;
//    cout<<"items in set = "<<hashSize*factorSize<<endl;
//    cout<<"items in 3 sets = "<<3*hashSize*factorSize<<endl;


    first = unordered_set<uint64_t, Hasher>(hashSize*factorSize, Hasher(firstSeed));
    second = unordered_set<uint64_t, Hasher>(hashSize*factorSize, Hasher(secondSeed));
    third = unordered_set<uint64_t, Hasher>(hashSize*factorSize, Hasher(thirdSeed));


    tableRealSize = first.bucket_count();

//    cout<<"tableRealSize in each bin = "<<tableRealSize<<endl;

//    while(tableRealSize*3/c1 < hashSize){
//        first = unordered_set<uint64_t, Hasher>(tableRealSize + 1, Hasher(firstSeed));
//        second = unordered_set<uint64_t, Hasher>(tableRealSize + 1, Hasher(secondSeed));
//        third = unordered_set<uint64_t, Hasher>(tableRealSize + 1, Hasher(thirdSeed));
//
//        tableRealSize = first.bucket_count();
//            cout<<"tableRealSize = "<<tableRealSize<<endl;
//    }

    first.max_load_factor(3);
    second.max_load_factor(3);
    third.max_load_factor(3);

//    hashSize = tableRealSize*3/c1;

//        cout<<"new hashSize = "<<hashSize<<endl;
}

void OBD3Tables::init() {

    OBDTables::init();
    first.clear();
    second.clear();
    third.clear();
}

vector<uint64_t> OBD3Tables::dec(uint64_t key){

//    auto keyIndices = indices[key];
//    if(keyIndices.size() == 0) {
    vector<uint64_t> keyIndices;
    keyIndices.push_back(first.bucket(key));
    keyIndices.push_back(tableRealSize + second.bucket(key));
    keyIndices.push_back(2 * tableRealSize + third.bucket(key));

    auto dhBits = getDHBits(key);
    uint64_t mask = 1;
    for (int j = 0; j < gamma; j++) {
        if ((dhBits & mask) == 1) {
            keyIndices.push_back(3 * tableRealSize + j); //put 1 in the right vertex of the edge
        }
        dhBits = dhBits >> 1;
    }
//        indices[key] = move(keyIndices);
//    }

    return keyIndices;
}

vector<uint64_t> OBD3Tables::decOptimized(uint64_t key){
//    auto keyIndices = indices[key];
//    if(keyIndices.size() == 0) {
//        cout<<"first time"<<endl;
    vector<uint64_t> keyIndices(11);
    keyIndices[0] = first.bucket(key);
    keyIndices[1] = tableRealSize + second.bucket(key);
    keyIndices[2] = 2 * tableRealSize + third.bucket(key);

    auto dhBits = getDHBits(key);
    byte* dhBytes = (byte*) (&dhBits);
    for (int j = 0; j < 8; j++) {
        keyIndices[3 + j] = dhBytes[j]; //put 1 in the right vertex of the edge
    }
//        indices[key] = move(keyIndices);

//    }

    return keyIndices;
}

vector<byte> OBD3Tables::decode(uint64_t key){
    auto indices = dec(key);

    GF2E val(0);
    for (int j=0; j<indices.size(); j++){
        val += variables[indices[j]]; //put 1 in the right vertex of the edge

    }

    vector<byte> valBytes(fieldSizeBytes);
    BytesFromGF2X(valBytes.data(), rep(val), fieldSizeBytes);

    return valBytes;
}



void OBD3Tables::fillTables(){

    for (int i=0; i<hashSize; i++){

//            cout<<"key is "<<keys[i]<<endl;
//        auto pair = first.insert(keys[i]);
        first.insert(keys[i]);
        second.insert(keys[i]);
        third.insert(keys[i]);

//        cout<<"first bucket = "<<first.bucket(keys[i])<<" second bucket = "<<second.bucket(keys[i])<<" third bucket = "<<third.bucket(keys[i])<<endl;

//        if (pair.second == false){
//            cout<<"key = "<<keys[i]<<" i = "<<i<<endl;
//        }
    }


//        cout << "first set contains " << first.size() << endl;
//        cout << "second set contains " << second.size() << endl;
//        cout << "third set contains " << third.size() << endl;


}

int OBD3Tables::peeling() {

    peelingVector.resize(hashSize);
    peelingCounter = 0;
    int counterInLoop = 1;

    queue<int> queueFirst;
    queue<int> queueSecond;
    queue<int> queueThird;

//    cout << "in peeling" << endl;
//    cout<<"first loop"<<endl;

//    auto start = high_resolution_clock::now();

    //Goes on the first hash
    for (int position = 0; position < tableRealSize; position++) {
        if (first.bucket_size(position) == 1) {
            //Delete the vertex from the graph
            auto key = *first.begin(position);
//                cout << "remove key " << key << endl;
            counterInLoop++;
            peelingVector[peelingCounter++] = key;
            first.erase(key);

            //Update the second vertex on the edge
            second.erase(key);
            third.erase(key);
        }
    }

//    auto end = high_resolution_clock::now();
//    auto duration = duration_cast<milliseconds>(end-start).count();
//        cout << "time in milliseconds for first peel: " << duration << endl;

//    start = high_resolution_clock::now();
    int bucketInd;
    //Goes on the second has
    for (int position = 0; position < tableRealSize; position++) {
        if (second.bucket_size(position) == 1) {
            //Delete the vertex from the graph
            auto key = *second.begin(position);
            second.erase(key);
//                cout << "remove key " << key << endl;
            counterInLoop++;
            peelingVector[peelingCounter++] = key;

            bucketInd = first.bucket(key);
            first.erase(key);

            if (first.bucket_size(bucketInd) == 1)
                queueFirst.push(bucketInd);

            //Update the second vertex on the edge
            third.erase(key);
        }
    }

//    end = high_resolution_clock::now();
//    duration = duration_cast<milliseconds>(end-start).count();
//       cout << "time in milliseconds for second peel: " << duration << endl;

//    start = high_resolution_clock::now();
    for (int position = 0; position < tableRealSize; position++) {
        if (third.bucket_size(position) == 1) {
            //Delete the vertex from the graph
            auto key = *third.begin(position);
            third.erase(key);
//                cout << "remove key " << key << endl;
            counterInLoop++;
            peelingVector[peelingCounter++] = key;

            bucketInd = first.bucket(key);
            first.erase(key);

            if (first.bucket_size(bucketInd) == 1)
                queueFirst.push(bucketInd);

            bucketInd = second.bucket(key);
            second.erase(key);

            if (second.bucket_size(bucketInd) == 1)
                queueSecond.push(bucketInd);

        }
    }

//    end = high_resolution_clock::now();
//    duration = duration_cast<milliseconds>(end-start).count();
//       cout << "time in milliseconds for third peel: " << duration << endl;

//       cout << "peelingCounter : " << peelingCounter << endl;
//        cout << "hashSize : " << hashSize << endl;
//
//        cout << "queueFirst.size() : " << queueFirst.size() << endl;
//        cout << "queueSecond.size() : " << queueSecond.size() << endl;
//        cout << "queueThird.size() : " << queueThird.size() << endl;


//    start = high_resolution_clock::now();
    //handle the queues one by one
    while (queueFirst.size() != 0 ||
           queueSecond.size() != 0 ||
           queueThird.size() != 0) {

        handleQueue(queueFirst, first, queueSecond, second, queueThird, third);

        handleQueue(queueSecond, second, queueFirst, first, queueThird, third);

        handleQueue(queueThird, third, queueFirst, first, queueSecond, second);

    }

//    end = high_resolution_clock::now();
//    duration = duration_cast<milliseconds>(end-start).count();
//      cout << "time in milliseconds for peel queues: " << duration << endl;

    if (peelingCounter != hashSize) {
        cout << "2 core contain : " << hashSize - peelingCounter << endl;
    }
//        cout << "hashSize : " << hashSize << endl;


    if(reportStatistics==1) {

        statisticsFile << "" << ", \n";
    }

    if (hashSize - peelingCounter > v){
        return 0; //Failure
    }
    else return 1;

}

void OBD3Tables::handleQueue(queue<int> &queueMain, unordered_set<uint64_t, Hasher> &main,
                             queue<int> &queueOther1, unordered_set<uint64_t, Hasher> &other1,
                             queue<int> &queueOther2,unordered_set<uint64_t, Hasher> &other2) {

    int bucketInd;
    for(int i=0; i < queueMain.size(); i++){

        int pos = queueMain.front();
        queueMain.pop();
        if(main.bucket_size(pos) == 1) {
            auto key = *main.begin(pos);
            main.erase(key);
//                cout << "remove key " << key << endl;
            peelingVector[peelingCounter++] = key;

            bucketInd = other1.bucket(key);
            other1.erase(key);

            if (other1.bucket_size(bucketInd) == 1)
                queueOther1.push(bucketInd);

            bucketInd = other2.bucket(key);
            other2.erase(key);

            if (other2.bucket_size(bucketInd) == 1)
                queueOther2.push(bucketInd);

        }
    }
}


void OBD3Tables::generateExternalToolValues(){


    // the rows count is the number of edges left after peeling
    //columns count is number of vertexes and gamma bits.

    auto start = high_resolution_clock::now();
    int matrixSize = hashSize - peelingCounter;
    GF2EMatrix matrix(matrixSize);

//    cout<<"num of rows = "<<matrixSize<<endl;
//    cout<<"num of cols = "<<3*matrixSize + gamma<<endl;
    GF2EVector values(matrixSize);

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end-start).count();

//    cout << "construct time in milliseconds for protocol: " << duration << endl;

    unordered_map<uint64_t, int> firstTableCols;
    unordered_map<uint64_t, int> secondTableCols;
    unordered_map<uint64_t, int> thirdTableCols;

//    cout<<"matrix:"<<endl;
//    for (int i=0; i<first.size(); i++){
//        for (int j=0; j<2*tableRealSize+gamma; j++){
//            cout<<matrix[i][j]<<" ";
//        }
//        cout<<endl;
//    }
    //Get all the edges that are in the graph's circles and calc the polynomial values that should be for them.

//    start = high_resolution_clock::now();
    int rowCounter = 0;
    int firstColsCounter = 0;
    int secondColsCounter = 0;
    int thirdColsCounter = 0;

    int firstPos, secondPos, thirdPos;
    for (int i=0; i<tableRealSize; i++){
        if (first.bucket_size(i) > 1){
            for (auto key = first.begin(i); key!= first.end(i); ++key){

                matrix[rowCounter].resize(3*matrixSize+gamma);
                if (firstTableCols.find(i) == firstTableCols.end()){
                    firstTableCols.insert({i, firstColsCounter});
                    firstColsCounter++;
                }

                int secondIndex = second.bucket(*key);
                if (secondTableCols.find(secondIndex) == secondTableCols.end()){
                    secondTableCols.insert({secondIndex, secondColsCounter});
                    secondColsCounter++;

                }
                int thirdIndex = third.bucket(*key);
                if (thirdTableCols.find(thirdIndex) == thirdTableCols.end()){
                    thirdTableCols.insert({thirdIndex, thirdColsCounter});
                    thirdColsCounter++;

                }
                firstPos = firstTableCols[i];
                secondPos = secondTableCols[secondIndex];
                thirdPos = thirdTableCols[thirdIndex];
//                cout<<"key "<<*key<<" first hash val = "<<i<< "and index "<<firstTableCols[i]<<" in the first cols"<<endl;
//                cout<<"key "<<*key<<" second hash val = "<<secondIndex<<"and index "<<secondTableCols[secondIndex]<<" in the second cols"<<endl;


                matrix[rowCounter][firstPos] = to_GF2E(1); //put 1 in the left vertex of the edge
                matrix[rowCounter][matrixSize + secondPos] = to_GF2E(1); //put 1 in the right vertex of the edge
                matrix[rowCounter][2*matrixSize + thirdPos] = to_GF2E(1); //put 1 in the right vertex of the edge
                sign[i] = 1;
                sign[tableRealSize + secondIndex] = 1;
                sign[2*tableRealSize + thirdIndex] = 1;

                auto dhBits = getDHBits(*key);
//                cout<<"DH bits: "<<dhBits<<endl;
                uint64_t mask = 1;
                for (int j=0; j<gamma; j++){
//                    cout<<(dhBits & mask)<<" ";
                    matrix[rowCounter][ 3*matrixSize + j] = to_GF2E(dhBits & mask); //put 1 in the right vertex of the edge
                    dhBits = dhBits >> 1;

                }
//                cout<<endl;
                values[rowCounter] = vals[*key];
                rowCounter++;

            }
        }
    }

//    end = high_resolution_clock::now();
//    duration = duration_cast<milliseconds>(end-start).count();
//
//    cout << "fill time in milliseconds: " << duration << endl;

//    cout<<"matrix:"<<endl;
//    for (int i=0; i<rowCounter; i++){
//        for (int j=0; j<2*rowCounter+gamma; j++){
//            cout<<matrix[i][j]<<" ";
//        }
//        cout<<endl;
//    }

//    cout<<"num of equations =  "<<rowCounter<<endl;

    if(reportStatistics==1) {

        statisticsFile << rowCounter << ", \n";
    }

//    start = high_resolution_clock::now();

    GF2EVector variablesSlim(3*matrixSize + gamma);
    //TODO call the solver and get the results in variables
    solve_api(matrix, values, variablesSlim, fieldSize);

//    end = high_resolution_clock::now();
//    duration = duration_cast<milliseconds>(end-start).count();
//
//    cout << "solver time in milliseconds: " << duration << endl;

//    start = high_resolution_clock::now();
    for (int i=0; i<tableRealSize; i++) {
        if (first.bucket_size(i) > 1) {
            for (auto key = first.begin(i); key != first.end(i); ++key) {

                int secondIndex = second.bucket(*key);
                int thirdIndex = third.bucket(*key);
                variables[i] = variablesSlim[firstTableCols[i]];
                variables[tableRealSize + secondIndex] = variablesSlim[matrixSize + secondTableCols[secondIndex]];
                variables[2*tableRealSize + thirdIndex] = variablesSlim[2*matrixSize + thirdTableCols[thirdIndex]];


            }
        }
    }

    for (int i=0; i<gamma; i++){
        variables[3*tableRealSize + i] = variablesSlim[3*matrixSize + i];
    }

//    end = high_resolution_clock::now();
//    duration = duration_cast<milliseconds>(end-start).count();
//
//    cout << "receive solver variables took: " << duration << endl;


//    cout<<"variables:"<<endl;
//    for (int i=0; i<variables.size(); i++){
//        cout<<"variable["<<i<<"] = "<<variables[i]<<endl;
//    }
}




void OBD3Tables::unpeeling(){
//    cout<<"in unpeeling"<<endl;
    uint64_t key;
    byte* randomVal;
    GF2E dhBitsVal;
    GF2X temp;
    osuCrypto::PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    while (peelingCounter > 0){
//            cout<<"key = "<<key<<endl;
        key = peelingVector[--peelingCounter];
        auto indices = dec(key);
//cout<<"indices = "<<endl;
//for (int i=0; i<indices.size(); i++){
//    cout<<indices[i]<<" ";
//}
//cout<<endl;
        dhBitsVal = 0;
        for (int j=3; j<indices.size(); j++){
            dhBitsVal += variables[indices[j]]; //put 1 in the right vertex of the edge

//            cout<<"variable in "<<indices[j]<<" place = "<<variables[2*tableRealSize+ indices[j]]<<endl;
        }
        if (variables[indices[0]] == 0 && sign[indices[0]] == 0){

            if (variables[indices[1]] == 0 && sign[indices[1]] == 0){
//                randomVal = prg.getPRGBytesEX(fieldSizeBytes);
                vector<byte> r;
                r.resize(fieldSizeBytes);
                GF2XFromBytes(temp, (unsigned char *)&r ,fieldSizeBytes);
                variables[indices[1]] = to_GF2E(temp);
            }

            if (variables[indices[2]] == 0 && sign[indices[2]] == 0) {
//                randomVal = prg.getPRGBytesEX(fieldSizeBytes);
//                randomVal = 0;
                vector<byte> r;
                r.resize(fieldSizeBytes);
                GF2XFromBytes(temp, (unsigned char *)&r, fieldSizeBytes);
                variables[indices[2]] = to_GF2E(temp);
            }

            variables[indices[0]] = vals[key] + variables[indices[1]] + variables[indices[2]] + dhBitsVal;

//                cout<<"set RANDOM value "<<variables[indices[0]]<<" in index "<<indices[0]<<endl;
        } else if (variables[indices[1]] == 0 && sign[indices[1]] == 0){

            if (variables[indices[2]] == 0 && sign[indices[2]] == 0) {
//                randomVal = prg.getPRGBytesEX(fieldSizeBytes);
                vector<byte> r;
                r.resize(fieldSizeBytes);
                GF2XFromBytes(temp, (unsigned char *)&r, fieldSizeBytes);
                variables[indices[2]] = to_GF2E(temp);
            }

            variables[indices[1]] = vals[key] + variables[indices[0]] + variables[indices[2]] + dhBitsVal;

        } else if  (variables[indices[2]] == 0 && sign[indices[2]] == 0){
            variables[indices[2]] = vals[key] + variables[indices[0]] + variables[indices[1]] + dhBitsVal;
        }
    }
//    cout<<"peelingCounter = "<<peelingCounter<<endl;

//    cout<<"variables:"<<endl;
//    for (int i=0; i<variables.size(); i++){
//        cout<<"variable["<<i<<"] = "<<variables[i]<<" ";
//    }
//    cout<<endl;
}

bool OBD3Tables::checkOutput(){
    uint64_t key;
    GF2E val, dhBitsVal;
    bool error = false;


    for (int i=0; i<hashSize; i++){
        key = keys[i];
        val = vals[key];

        auto indices = dec(key);

        dhBitsVal = 0;
        for (int j=3; j<indices.size(); j++){
            dhBitsVal += variables[indices[j]]; //put 1 in the right vertex of the edge

        }

        if ((variables[indices[0]] + variables[indices[1]] +  variables[indices[2]] + dhBitsVal) == val) {
//            if (i%100000 == 0)
//                cout<<"good value!!! val = "<<val<<endl;
        } else {//if (!hasLoop()){
            error = true;
            cout<<"invalid value :( val = "<<val<<" wrong val = "<<(variables[indices[0]] + variables[indices[1]] + variables[indices[2]] + dhBitsVal)<<endl;
            cout<<"variables["<<indices[0]<<"] = "<<variables[indices[0]]<<endl;
            cout<<"variables["<<indices[1]<<"] = "<<variables[indices[1]]<<endl;
            cout<<"variables["<<indices[2]<<"] = "<<variables[indices[2]]<<endl;
            cout<<"dhBitsVal = "<<dhBitsVal<<endl;
        }

    }
    if (!error){
        cout<<"success!!!! dictionary is fine."<<endl;
    }
    return error;
}

bool OBD3Tables::hasLoop(){
    for (int position = 0; position<tableRealSize; position++) {
        if (first.bucket_size(position) > 1) {
            return true;
        }
    }
    return false;
}

StarDictionary::StarDictionary(int numItems, double c1, double c2, int q, int fieldSize, int gamma, int v, int numThreads) : ObliviousDictionary(numItems, fieldSize, gamma, v), q(q) {

    this->numThreads = numThreads;
    bins.resize(q+1);
    center = q;

    numItemsForBin = c2*(numItems/q);
    cout<<"gamma = "<<gamma<<endl;
    cout<<"numItemsForBin = "<<numItemsForBin<<endl;
    gamma = 40 + 0.5*log(numItemsForBin);
    cout<<"gamma = "<<gamma<<endl;

    cout<<"v inside bin = "<<0.5*log(numItemsForBin)<<endl;
    for (int i=0; i<q+1; i++){
        bins[i] = new OBD3Tables(numItemsForBin, c1, fieldSize, gamma, v);
    }

    int tableRealSize = bins[0]->getTableSize();
    cout<<"variablesSize = "<<tableRealSize<<endl;

    //the value is fixed for tests reasons
    int binsHashSeed = 4;
    hashForBins = Hasher(binsHashSeed);

    cout << "after create sets" << endl;
    cout << "tableRealSize = " << tableRealSize << endl;
    cout << "hashSize = " << hashSize << endl;
}

void StarDictionary::setKeysAndVals(vector<uint64_t>& keys, vector<byte>& values){
    ObliviousDictionary::setKeysAndVals(keys, values);
    keysForBins.resize(q, vector<uint64_t>(numItemsForBin));
    int fieldSizeBytes = fieldSize % 8 == 0 ? fieldSize/8 : fieldSize/8 + 1;
    valsForBins.resize(q, vector<byte>(numItemsForBin*fieldSizeBytes));
    vector<int> numItemInBin(q, 0);

    int size = keys.size();
    int64_t index, indexInInnerBin;
    for (int i=0; i<size; i++){
        index = hashForBins(keys[i]) % q;
        indexInInnerBin = numItemInBin[index];
        keysForBins[index][indexInInnerBin] = keys[i];
        memcpy(valsForBins[index].data() + indexInInnerBin*fieldSizeBytes, values.data() + i*fieldSizeBytes, fieldSizeBytes);
        numItemInBin[index] = numItemInBin[index]+1;
    }


    //fill dummy values if the bin is not full
    for (int i=0; i<q; i++){
        indexInInnerBin = numItemInBin[i];
        int numElementsToFill = numItemsForBin - indexInInnerBin;
//        prg.getPRGBytes((byte*)(keysForBins[i].data() + indexInInnerBin), numElementsToFill*sizeof (uint64_t));
//        prg.getPRGBytes((byte*)(valsForBins[i].data() + indexInInnerBin*fieldSizeBytes), numElementsToFill*fieldSizeBytes);

        //set the keys and values of the bin
        //TODO no need to set values here
        bins[i]->setKeysAndVals(keysForBins[i], valsForBins[i]);
    }

}

void StarDictionary::init() {

    for (int i=0; i<q; i++){
        bins[i]->init();
        bins[i]->fillTables();
    }
}

vector<uint64_t> StarDictionary::dec(uint64_t key){

//    auto keyIndices = indices[key];
//    if (keyIndices.size() == 0) {
    int binIndex = hashForBins(key) % q;
    int innerIndicesSize = bins[0]->getTableSize();
    //    cout<<"bins[0]->getTableSize() = "<<bins[0]->getTableSize()<<endl;
    //    cout<<"gamma = "<<gamma<<endl;
    //    cout<<"innerSize in dec = "<<innerIndicesSize<<endl;
    auto binIndices = bins[binIndex]->dec(key);

    //    cout<<"binIndex =  "<<binIndex<<" numItemsForBin = "<<numItemsForBin<<endl;


    auto centerIndices = bins[center]->dec(key);

    vector<uint64_t> keyIndices(binIndices.size() + centerIndices.size()); //Will hold the indices of the big array

    int startIndex = binIndex * innerIndicesSize;
    for (int i = 0; i < binIndices.size(); i++) {
        keyIndices[i] = startIndex + binIndices[i];

    }

    startIndex = center * innerIndicesSize;
    for (int i = 0; i < centerIndices.size(); i++) {
        keyIndices[binIndices.size() + i] = startIndex + centerIndices[i];

    }

//        indices[key] = move(keyIndices);
//    }
    return keyIndices;
}

vector<uint64_t> StarDictionary::decOptimized(uint64_t key){
//    auto keyIndices = indices[key];
//    if(keyIndices.size() == 0) {
//        cout<<"first time"<<endl;
    int binIndex = hashForBins(key) % q;
    int innerIndicesSize = bins[0]->getTableSize();
    //    cout<<"bins[0]->getTableSize() = "<<bins[0]->getTableSize()<<endl;
    //    cout<<"gamma = "<<gamma<<endl;
    //    cout<<"innerSize in dec = "<<innerIndicesSize<<endl;
    auto binIndices = bins[binIndex]->decOptimized(key);

    //    cout<<"binIndex =  "<<binIndex<<" numItemsForBin = "<<numItemsForBin<<endl;


    auto centerIndices = bins[center]->decOptimized(key);

    vector<uint64_t> keyIndices(1 + binIndices.size() + centerIndices.size()); //Will hold the indices of the big array
    keyIndices[0] = binIndex;

    int startIndex = binIndex * innerIndicesSize;
    for (int i = 0; i < 3; i++) {
        keyIndices[1 + i] = startIndex + binIndices[i];
    }

    for (int i = 0; i < 8; i++) {
        keyIndices[4 + i] = binIndices[3 + i];
    }

    startIndex = center * innerIndicesSize;
    for (int i = 0; i < 3; i++) {
        keyIndices[1 + binIndices.size() + i] = startIndex + centerIndices[i];
    }

    for (int i = 0; i < 8; i++) {
        keyIndices[4 + binIndices.size() + i] = centerIndices[3 + i];
    }

    return keyIndices;
}

vector<byte> StarDictionary::decode(uint64_t key){
    int index = hashForBins(key) % q;

    vector<byte> first = bins[index]->decode(key);
    vector<byte> second = bins[center]->decode(key);


    for (int i=0; i<first.size(); i++){
        first[i] ^= second[i];
    }

    return first;
}

bool StarDictionary::encode() {

    auto start = high_resolution_clock::now();

    int sizeForEachThread;
    if (q <= numThreads){
        numThreads = q;
        sizeForEachThread = 1;
    } else{
        sizeForEachThread = (q + numThreads - 1)/ numThreads;
    }
    vector<thread> threads(numThreads);
    vector<int> failureIndices(numThreads);


    for (int t=0; t<numThreads; t++) {

        if ((t + 1) * sizeForEachThread <= q) {
            threads[t] = thread(&StarDictionary::peelMultipleBinsThread, this, t * sizeForEachThread, (t + 1) * sizeForEachThread, ref(failureIndices),t);
        } else {
            threads[t] = thread(&StarDictionary::peelMultipleBinsThread, this, t * sizeForEachThread, q, ref(failureIndices),t);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }

    int failureIndex = -1;//-1 means no failures, index means one failure, -2 means at least 2 failures
    for (int t=0; t<numThreads; t++) {

        if(failureIndices[t]==-1){}//do nothing
        else if (failureIndices[t]>-1) {//one bin failure

            if(failureIndex==-1) {
                failureIndex = failureIndices[t];//indicates failure, 2 bins have failed
            }
            else{
                failureIndex = -2;
            }
        } else {
            failureIndex = -2;
        }
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end-start).count();
    cout << "time in milliseconds for peel all bins: " << duration << endl;

    start = high_resolution_clock::now();
    cout<<"failure index = "<<failureIndex<<endl;
    if (failureIndex == -1){//all bins have peeled succesfully
        bins[center]->generateRandomEncoding();
        cout<<"no failure. generate random values for center"<<endl;

    } else if (failureIndex > -1){//one bin has failed
        cout<<"failure in bin number "<<failureIndex<<". generate random values for center"<<endl;
        bins[failureIndex]->generateRandomEncoding();

        vector<byte> valsForCenter(numItemsForBin*fieldSizeBytes);

        for (int i=0; i<numItemsForBin; i++){
            auto binVal = bins[failureIndex]->decode(keysForBins[failureIndex][i]);

            for (int j=0; j<fieldSizeBytes; j++){
                valsForCenter[i*fieldSizeBytes + j] = binVal[j]^valsForBins[failureIndex][i*fieldSizeBytes + j];
            }
        }

        bins[center]->setKeysAndVals(keysForBins[failureIndex], valsForCenter);
        bins[center]->init();
        bins[center]->fillTables();
        bins[center]->peeling();
        bins[center]->generateExternalToolValues();
        bins[center]->unpeeling();
    }
    else {//unlikely, means that 2 or more bins have failed - negligable
        cout<<"2 or more bins have failed"<<endl;
        return false;
    }

    end = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(end-start).count();
    cout << "time in milliseconds for generate center values: " << duration << endl;

    start = high_resolution_clock::now();
//    vector<byte> centerValues = bins[center]->getVariables();


    for (int t=0; t<numThreads; t++) {

        if ((t + 1) * sizeForEachThread <= q) {
            threads[t] = thread(&StarDictionary::setNewValsThread, this, t * sizeForEachThread, (t + 1) * sizeForEachThread, failureIndex);
        } else {
            threads[t] = thread(&StarDictionary::setNewValsThread, this, t * sizeForEachThread, q,failureIndex);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }

    //Cannot be done using threads since GF2X fails
    for (int i=0; i < q; i++){
        if (i != failureIndex){

            bins[i]->setKeysAndVals(keysForBins[i], valsForBins[i]);
        }
    }
    end = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(end-start).count();
    cout << "time in milliseconds for set new vals for all bins: " << duration << endl;

    start = high_resolution_clock::now();
    for (int t=0; t<numThreads; t++) {

        if ((t + 1) * sizeForEachThread <= q) {
            threads[t] = thread(&StarDictionary::unpeelMultipleBinsThread, this, t * sizeForEachThread, (t + 1) * sizeForEachThread, failureIndex);
        } else {
            threads[t] = thread(&StarDictionary::unpeelMultipleBinsThread, this, t * sizeForEachThread, q,failureIndex);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }


    end = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(end-start).count();
    cout << "time in milliseconds for unpeel all bins: " << duration << endl;

    return true;

}

void StarDictionary::setNewValsThread(int start, int end, int failureIndex){
    for (int i=start; i < end; i++) {
        if (i != failureIndex) {

            for (int j = 0; j < numItemsForBin; j++) {
                auto binVal = bins[center]->decode(keysForBins[i][j]);

                for (int k = 0; k < fieldSizeBytes; k++) {
                    valsForBins[i][j * fieldSizeBytes + k] = binVal[k] ^ valsForBins[i][j * fieldSizeBytes + k];
                }
            }
            //            bins[i]->generateExternalToolValues();
            //            bins[i]->unpeeling();
        }
    }
}

void StarDictionary::unpeelMultipleBinsThread(int start, int end, int failureIndex)  {
    for (int i=start; i < end; i++){
        if (i != failureIndex){

//            for (int j=0; j < numItemsForBin; j++){
//                auto binVal = bins[center]->decode(keysForBins[i][j]);
//
//                for (int k=0; k < fieldSizeBytes; k++){
//                    valsForBins[i][j * fieldSizeBytes + k] = binVal[k] ^ valsForBins[i][j * fieldSizeBytes + k];
//                }
//            }
//
//            bins[i]->setKeysAndVals(keysForBins[i], valsForBins[i]);
            bins[i]->generateExternalToolValues();
            bins[i]->unpeeling();
        }
    }
}

void StarDictionary::peelMultipleBinsThread(int start, int end, vector<int> &failureIndices, int threadId) {
    int succeed, failureIndex = -1;

    for (int i=start; i < end; i++){
        succeed = bins[i]->peeling();
        if (!succeed) {
            if(failureIndex==-1)
                failureIndex = i;
            else if (failureIndex>-1)
                failureIndex = -2;//indicates failure, 2 bins have failed
        }
    }
    failureIndices[threadId] = failureIndex;
}


bool StarDictionary::checkOutput(){
    uint64_t key;
    GF2X temp;
    GF2E val, decVal;
    bool error = false;


    for (int i=0; i<hashSize; i++){
        key = keys[i];
        val = vals[key];

        auto decValBytes = decode(key);
        GF2XFromBytes(temp, decValBytes.data(), fieldSizeBytes);
        decVal = to_GF2E(temp);
        if (decVal == val) {
//            if (i%100000 == 0)
//                cout<<"good value!!! val = "<<val<<endl;
        } else {//if (!hasLoop()){
            error = true;
//            cout << "invalid value :( val = " << val << " wrong val = " << decVal << endl;
        }


    }
    if (!error){
        cout<<"success!!!! dictionary is fine."<<endl;
    } else {
        cout<<"error!!!! dictionary is bad."<<endl;
    }
    return error;
}

bool StarDictionary::checkOutput(uint64_t key, int valIndex){
    bool error = false;

    vector<byte> temp1(fieldSizeBytes, 0);
    vector<byte> temp2(fieldSizeBytes, 0);

    vector<byte> variables = getVariables();
    int index = hashForBins(key) % q;

    auto indices = bins[index] -> dec(key);

    int size = bins[0]->getTableSize();
    for (int i=0; i<indices.size(); i++){
        for (int j=0; j<fieldSizeBytes; j++){
            temp1[j] ^= bins[index]->getVariables()[indices[i]*fieldSizeBytes + j];
        }

    }

    auto rightVal = bins[index] -> decode(key);
    for (int j=0; j<fieldSizeBytes; j++) {
        if (temp1[j] == rightVal[j]) {
//            if (i%100000 == 0)
//                cout<<"good value!!! val = "<<val<<endl;
        } else {//if (!hasLoop()){
            cout << "error in index bin"<< endl;
        }
    }


    indices = bins[center] -> dec(key);

    for (int i=0; i<indices.size(); i++){
        for (int j=0; j<fieldSizeBytes; j++){
//            temp[j] ^= variables[center*fieldSizeBytes*size + i*fieldSizeBytes + j];
            temp2[j] ^= bins[center]->getVariables()[indices[i]*fieldSizeBytes + j];
        }

    }
    rightVal = bins[center] -> decode(key);
    for (int j=0; j<fieldSizeBytes; j++) {
        if (temp2[j] == rightVal[j]) {
//            if (i%100000 == 0)
//                cout<<"good value!!! val = "<<val<<endl;
        } else {//if (!hasLoop()){
            cout << "error in center bin"<< endl;
        }
    }

//        GF2XFromBytes(temp, decValBytes.data(), fieldSizeBytes);
//        decVal = to_GF2E(temp);
    for (int j=0; j<fieldSizeBytes; j++) {
        if (temp1[j]^temp2[j] == values[valIndex * fieldSizeBytes + j]) {
//            if (i%100000 == 0)
//                cout<<"good value!!! val = "<<val<<endl;
        } else {//if (!hasLoop()){
            error = true;
            cout << "invalid value :( "<< endl;
        }
    }


    if (!error){
        cout<<"success!!!! dictionary is fine."<<endl;
    }
    return error;
}

vector<byte> StarDictionary::getVariables()  {
//    cout<<"in StarDictionary getVariables"<<endl;
    auto binVariables = bins[0]->getVariables();
    int innerSize = binVariables.size();
//    cout<<"innerSize in getVariables = "<<innerSize/fieldSizeBytes<<endl;
    vector<byte> variables((q+1)*innerSize);
    memcpy(variables.data(), binVariables.data(), innerSize);

    for (int i=1; i<q+1; i++){
        binVariables = bins[i]->getVariables();
        memcpy(variables.data() + i*innerSize, binVariables.data(), innerSize);
    }
    return variables;
}