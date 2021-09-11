cmake_minimum_required(VERSION 3.10)

set(SOURCE_FILES ObliviousDictionary.cpp gf2e_mat_solve.cpp)

add_library(libPaXoS ${SOURCE_FILES})

#NTL
set(NTL_Lib_Dirs "${NTL_Dirs}/src/")
set(NTL_Include_Dirs "${NTL_Dirs}/include/")
set(NTL_LIB "${NTL_Lib_Dirs}libntl.a")
if(NOT EXISTS "${NTL_LIB}")
	# we failed to find it, try using find_library
	find_library(
			NTL_LIB
			NAMES ntl
			HINTS NTL_Lib_Dirs)

	# if we still cant fint it, throw an error
	if(NOT NTL_LIB)
		Message(${NTL_LIB})
		message(FATAL_ERROR "Failed to find NTL at ${NTL_Lib_Dirs} or at system locations." )
	endif()
else()
	include_directories(${NTL_Include_Dirs})
	#message(" ----  NTL -----  ${NTL_Include_Dirs}")
endif()


find_library(
		xxHash_LIB
		NAMES xxhash
		HINTS ./xxHash)

target_link_libraries(libPaXoS
		${NTL_LIB}
		${xxHash_LIB}
		linbox
		iml
        boost_system
        pthread
        crypto
        dl
        blas
        givaro
        gmp
        gomp
)