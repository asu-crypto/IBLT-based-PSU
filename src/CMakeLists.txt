cmake_minimum_required(VERSION 3.9.4)
project(2pc-psu)

set(CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 20)

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)

if(NOT DEFINED VOLEPSI_INSTALL_PATH)
  set(VOLEPSI_INSTALL_PATH "${CMAKE_SOURCE_DIR}/../volepsi")
endif()

if(NOT DEFINED CATCH2_INSTALL_PATH)
  set(CATCH2_INSTALL_PATH "${CMAKE_SOURCE_DIR}/../catch2")
endif()

set (CMAKE_PREFIX_PATH "${VOLEPSI_INSTALL_PATH};${CATCH2_INSTALL_PATH}")

find_package(Catch2 3 REQUIRED)
find_package(volePSI REQUIRED)
find_package(coproto REQUIRED)
find_package(unordered_dense CONFIG REQUIRED)
find_package(OpenMP REQUIRED)

set(BUILD_PROFILING_EXECUTABLES OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_options(-O3 -Wall -Wextra -Wpedantic)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Profile")
  add_compile_options(-O3)
  add_compile_options(-pg)
  add_compile_options(-ftree-vectorizer-verbose=6)
  #add_compile_options(-fopenmp)
  add_link_options(-pg)
  set(BUILD_PROFILING_EXECUTABLES ON)
  set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -march=native -ftree-vectorize -fopt-info-vec-optimized")

message(CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

set(SOURCES
  ${CMAKE_SOURCE_DIR}/iblt_h5.cpp
  ${CMAKE_SOURCE_DIR}/psu.cpp
)
set(HEADERS
  ${CMAKE_SOURCE_DIR}/iblt_h5.hpp
  ${CMAKE_SOURCE_DIR}/psu.h
)

if( supported )
    message(STATUS "IPO / LTO enabled")
else()
    message(SEND_ERROR "IPO / LTO not supported: <${error}>")
endif()

if(BUILD_TESTS)
    set(ALL_TESTS
        psu_test
        xxhash_test
    )

    set (TEST_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/tests)

    add_executable(psu_test ${TEST_SOURCE_PREFIX}/psu.test.cpp ${SOURCES})
    add_executable(xxhash_test ${TEST_SOURCE_PREFIX}/xxhash.test.cpp ${SOURCES})

    foreach(target ${ALL_TESTS})
        set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
        target_compile_features(${target} PUBLIC cxx_std_20)
        target_compile_options(${target} PRIVATE ${DEFAULT_COMPILER_OPTIONS_AND_WARNINGS})
        target_link_libraries(${target} PRIVATE Catch2::Catch2WithMain visa::volePSI xxhash coproto::coproto unordered_dense::unordered_dense)

        add_test(NAME ${target} COMMAND ${target})
    endforeach()
endif()

if(BUILD_BENCH)
   set(ALL_BENCHS
        psu_bench
        simd_bench
        #ot_reduc
        #iblt_h5_bench
        #bitvector_bench
        #multiaes_bench
        #preprocessing_bench
    )

    set (BENCH_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/benchmarks)
    
    add_executable(psu_bench ${BENCH_SOURCE_PREFIX}/psu.bench.cpp ${SOURCES})
    #add_executable(ot_reduc ${BENCH_SOURCE_PREFIX}/ot_reduc.bench.cpp ${SOURCES})    
    add_executable(simd_bench ${BENCH_SOURCE_PREFIX}/simd.bench.cpp ${SOURCES})
    #add_executable(bitvector_bench ${BENCH_SOURCE_PREFIX}/bitvector.bench.cpp ${SOURCES})
    #add_executable(multiaes_bench ${BENCH_SOURCE_PREFIX}/multiaes.bench.cpp ${SOURCES})
    #add_executable(preprocessing_bench ${BENCH_SOURCE_PREFIX}/preprocessing.bench.cpp ${SOURCES})
    #add_executable(iblt_h5_bench ${BENCH_SOURCE_PREFIX}/iblt_h5.bench.cpp ${SOURCES})

    foreach(target ${ALL_BENCHS})
        set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
        target_compile_features(${target} PUBLIC cxx_std_20)
        target_compile_options(${target} PRIVATE ${DEFAULT_COMPILER_OPTIONS_AND_WARNINGS})
        target_link_libraries(${target} PRIVATE Catch2::Catch2WithMain visa::volePSI coproto::coproto xxhash unordered_dense::unordered_dense)
        set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

        add_test(NAME ${target} COMMAND ${target})
    endforeach()
endif()

if(BUILD_PROFILING_EXECUTABLES)
  set(ALL_PROFILING_EXECUTABLES
    profiling_psu_with_local_sockets
  )

  set (PROFILING_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/profiling)

  foreach(target ${ALL_PROFILING_EXECUTABLES})
      add_executable(${target} ${PROFILING_SOURCE_PREFIX}/${target}.cpp ${SOURCES})
      target_link_libraries(${target} visa::volePSI coproto::coproto xxhash unordered_dense::unordered_dense)
      set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endforeach()
endif()

add_executable(psu_main ${CMAKE_SOURCE_DIR}/psu_main.cpp ${SOURCES})
target_link_libraries(psu_main visa::volePSI coproto::coproto xxhash unordered_dense::unordered_dense)

#target_link_libraries(opt_iblt_exp visa::volePSI)
#if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  #target_compile_definitions(opt_iblt_exp_h4 PRIVATE DEBUG_MODE)
  #target_compile_definitions(opt_iblt_exp_h5 PRIVATE DEBUG_MODE)
  #target_compile_definitions(pround_exps_h5 PRIVATE DEBUG_MODE)
  #target_compile_definitions(trypeel_main PRIVATE DEBUG_MODE)
  #target_compile_definitions(main_iblt_h5 PRIVATE DEBUG_MODE)
#endif()