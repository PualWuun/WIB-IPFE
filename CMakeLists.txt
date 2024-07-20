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
file(GLOB SOURCES "scheme_structure/*.cpp")
add_executable(IPFE_test_ibbe
        src/schemes/ibbe_pk_ipfe.cpp
        src/curve/params.cpp
        src/components/HIDparam.cpp
        src/components/ElementList.cpp
        src/components/MasterKey.cpp
        src/components/PublicKey.cpp
        src/components/SecretKey.cpp
        src/components/CipherText.cpp
        src/utils/func.cpp
        src/utils/utils.cpp
        unit_test/test_ibbe.cpp
        cjson/cJSON.c
        policy_resolution/policy_resolution.cpp
        policy_generation/policy_generation.cpp
        data_structure/multiway_tree.cpp
        data_structure/binary_tree.cpp
        data_structure/access_structure.cpp
        data_structure/element_t_matrix.cpp
        data_structure/element_t_vector.cpp
        data_structure/num_vector.cpp
        ${SOURCES}
        )
        
target_link_libraries(IPFE_test_ibbe pbc OpenSSL::SSL
        "/usr/local/lib/libpbc.a"
        "/usr/local/lib/libgmp.a")