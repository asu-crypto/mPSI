
## Installations
Tested with C++ compiler with C++14 support and Ubuntu 20.04.3 LTS.

### Required libraries
 
  1. Clone the project and enter its directory.
  2. Run <code>sudo apt install libntl-dev</code>
  3. Run <code>sudo apt install liblinbox-dev</code>
  4. Run <code>sudo apt install libgmp-dev</code>
  5. Run <code>sudo apt install libboost-system-dev</code>
  6. Run <code>sudo apt install libssl-dev</code>
  7. Run <code>sudo apt install libiml-dev</code>
  <br/> All the installations in one command: 
  <code>sudo apt install libntl-dev liblinbox-dev libgmp-dev libboost-system-dev
  libssl-dev libiml-dev</code>
  8. Run 'cd ./xxHash/'.
  9. Run 'make'.
  10. Run 'cd ..'.
  11. Run 'cmake .'.
  12. Run 'make'. 
  13. If the build fails due to an error in linbox/matrix/densematrix/blas-transposed-matrix.h:74:8, remove 
  the lines 72-74 from this file, according to the issue https://github.com/linbox-team/linbox/issues/116
  and commit https://github.com/linbox-team/linbox/commit/56be8673613fff87fb2329f71bceb0c793c00b82.
 
