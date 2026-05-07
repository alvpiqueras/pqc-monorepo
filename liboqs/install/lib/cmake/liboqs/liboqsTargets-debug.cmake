#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OQS::oqs" for configuration "Debug"
set_property(TARGET OQS::oqs APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(OQS::oqs PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/lib/oqs.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/oqs.dll"
  )

list(APPEND _cmake_import_check_targets OQS::oqs )
list(APPEND _cmake_import_check_files_for_OQS::oqs "${_IMPORT_PREFIX}/lib/oqs.lib" "${_IMPORT_PREFIX}/bin/oqs.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
