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
cd xxhash
make
RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo "Make of xxhash finished successfully!"
else
  echo "Make of xxhash failed. Quitting"
  exit 1
fi

RED='\033[0;31m'
NC='\033[0m' # No Color
echo -e "${RED}**Using ubuntu 18? You might have a problem building linbox! Check the readme file in libPaXoS for more information!**${NC}"
