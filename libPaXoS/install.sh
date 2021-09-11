#!/bin/bash -

echo "About to install dependencies"

sudo apt install gcc clang pentium-builder tcc

sudo apt install libntl-dev liblinbox-dev libgmp-dev libboost-system-dev libssl-dev libiml-dev

RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo "Install dependencies successfully!"
else
  echo "Failed while installing dependencies. Quitting"
  exit 1
fi

echo "About to make xxhash"
cd xxHash
make
RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo "Make of xxhash finished successfully!"
else
  echo "Make of xxhash failed. Quitting"
  exit 1
fi

cd /usr/include/linbox/matrix/densematrix/
LINE_OUTPUT=$(sed '70q;d' blas-transposed-matrix.h)

if [ "$LINE_OUTPUT" = "#if !defined(__INTEL_COMPILER) && !defined(__CUDACC__) & !defined(__clang__)$" ]; then
  echo "Older version of linbox detected. Patching it according to https://github.com/linbox-team/linbox/issues/116"
  sudo sed -i '70d' blas-transposed-matrix.h
  sudo sed -i '70d' blas-transposed-matrix.h
  sudo sed -i '70d' blas-transposed-matrix.h
  echo "Done patching the file. Linbox should be good to go now!"
fi
