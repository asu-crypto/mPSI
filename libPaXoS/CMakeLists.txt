
#project(fronend)


#############################################
#            Link our libraries             #
#############################################

#Probably need to find this dep and link it in a different way
link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

#############################################
#                 Link libOTe               #
#############################################


find_library(
    libOTe_Tests_LIB
    NAMES libOTe_Tests
    HINTS "${libOTe_Dirs}/lib/")

find_library(
    cryptoTools_Tests_LIB
    NAMES tests_cryptoTools
    HINTS "${libOTe_Dirs}/lib/")


#target_link_libraries(
#		$ENV{CMAKE_CURRENT_LIST_DIR}/xxHash/libxxhash.so givaro blas linbox iml
#		${NTL_Lib_Dirs}libntl.a gmp

#        $ENV{CMAKE_CURRENT_LIST_DIR}/libscapi/libscapi.a crypto
#)
