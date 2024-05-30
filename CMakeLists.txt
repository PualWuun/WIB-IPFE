cmake_minimum_required(VERSION 3.0)
project(WIB_IPFE)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_BUILD_TYPE "Debug")

find_package(OpenSSL REQUIRED)
include_directories(include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pthread -mavx2 -O3")
add_compile_options(-Wunknown-pragmas)

FIND_PACKAGE(OpenMP REQUIRED)
if (OPENMP_FOUND)
    message("OPENMP FOUND")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif ()

if (ENABLE_OMP)
    message("OpenMP enabled")
    add_definitions("-DParallel")
endif (ENABLE_OMP)

if (LOCAL_DEBUG)
    message("LOCAL_DEBUG enabled")
    add_definitions("-DDEBUG")
endif (LOCAL_DEBUG)

add_executable(IPFE_test 
        src/schemes/hid_pk_ipfe_song.cpp
        src/curve/params.cpp
        src/components/ElementList.cpp
        src/components/MasterKey.cpp
        src/components/PublicKey.cpp
        src/components/SecretKey.cpp
        src/components/CipherText.cpp
        src/components/HIDparam.cpp
        src/utils/func.cpp
        unit_test/test.cpp)
        
target_link_libraries(IPFE_test pbc OpenSSL::SSL
        "/usr/local/lib/libpbc.a"
        "/usr/local/lib/libgmp.a")

add_executable(IPFE_test_wib 
        src/schemes/wib_pk_ipfe.cpp
        src/curve/params.cpp
        src/components/ElementList.cpp
        src/components/MasterKey.cpp
        src/components/PublicKey.cpp
        src/components/SecretKey.cpp
        src/components/CipherText.cpp
        src/components/HIDparam.cpp
        src/utils/func.cpp
        unit_test/test_wib.cpp)
        
target_link_libraries(IPFE_test_wib pbc OpenSSL::SSL
        "/usr/local/lib/libpbc.a"
        "/usr/local/lib/libgmp.a")