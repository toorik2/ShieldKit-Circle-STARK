# Loaded immediately after BCHN's top-level project() by CMAKE_PROJECT_INCLUDE.
# Defer creation until the end of that directory so BCHN's static libraries
# already exist. This keeps the pinned source tree pristine.

if(NOT PROJECT_NAME STREQUAL "bitcoin-cash-node")
  return()
endif()

get_property(v17_bchn_assay_scheduled GLOBAL PROPERTY V17_BCHN_ASSAY_SCHEDULED)
if(v17_bchn_assay_scheduled)
  return()
endif()
set_property(GLOBAL PROPERTY V17_BCHN_ASSAY_SCHEDULED TRUE)

# This target needs the script dependency perimeter, not BCHN's unit/benchmark
# corpus. FORCE also reaches BCHN's generated nested native build.
set(ENABLE_TEST OFF CACHE BOOL "Build only the v17 assay perimeter" FORCE)
set(Boost_NO_WARN_NEW_VERSIONS ON CACHE BOOL "Pinned fallback Boost" FORCE)

if(NOT DEFINED V17_BCHN_ASSAY_SOURCE)
  message(FATAL_ERROR "V17_BCHN_ASSAY_SOURCE is required")
endif()

function(v17_add_bchn_assay)
  add_executable(v17-bchn-v29-assay "${V17_BCHN_ASSAY_SOURCE}")
  target_compile_features(v17-bchn-v29-assay PRIVATE cxx_std_20)
  target_include_directories(v17-bchn-v29-assay PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_BINARY_DIR}/src"
  )
  # BCHN's static perimeter contains a deliberate script/pubkey cycle:
  # bitcoinconsensus owns pubkey.cpp while script owns interpreter.cpp.
  # Repeat the archive after script so GNU ld rescans the required symbols.
  target_link_libraries(v17-bchn-v29-assay PRIVATE
    bitcoinconsensus script bitcoinconsensus
  )
  set_target_properties(v17-bchn-v29-assay PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
endfunction()

cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL v17_add_bchn_assay)
