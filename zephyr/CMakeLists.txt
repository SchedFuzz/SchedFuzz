# schedfuzz fuzzer application for Zephyr (default board qemu_cortex_m3).
# zephyr/run_fuzzer.sh configures, builds and runs it.
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(zephyr_fuzz)

target_sources(app PRIVATE src/main.c src/model_zephyr.c
                          ../core/fuzz_core.c 
                          ../core/structural_inv.c ../core/invariants.c
                          ../core/rt_invariants.c
                          ../core/op_ir.c
                          ../core/sigma_rt.c
                          ../core/wait_q_oracle.c)
target_include_directories(app PRIVATE src ../core)

# Forward -DSF_N_ITERS / -DSF_PEROP_CHECK to src/main.c as compile definitions.
foreach(_sf_var SF_N_ITERS SF_PEROP_CHECK)
    if(DEFINED ${_sf_var})
        target_compile_definitions(app PRIVATE ${_sf_var}=${${_sf_var}})
        message(STATUS "schedfuzz: ${_sf_var}=${${_sf_var}}")
    endif()
endforeach()
