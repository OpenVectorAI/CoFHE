# Findgmp
# -----------
#
# The module defines the following variables:
#
#     GMP_FOUND
#     GMP_INCLUDE_DIRS
#     GMP_LIBRARIES
#
# and the following imported target (if it does not already exist):
#
#  gmp::gmp - The gmp library
#
#
# Requires CMake >= 3.0

set (GMP_DIR "${GMP_DIR}" CACHE PATH "Directory to search for gmp")

# Look for the library
find_library (GMP_LIBRARY NAMES gmp HINTS "${GMP_DIR}" PATH_SUFFIXES lib)

# Might want to look close to the library first for the includes.
get_filename_component (_libdir "${GMP_LIBRARY}" PATH)

# Look for the C++ library
find_library (GMP_CPP_LIBRARY NAMES gmpxx HINTS "${_libdir}/.." "${GMP_DIR}"
                                          PATH_SUFFIXES lib)

# Look for the include directory
find_path (GMP_INC_DIR NAMES gmp.h
                         HINTS "${_libdir}/.." "${GMP_DIR}"
                         PATH_SUFFIXES include)

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args (gmp DEFAULT_MSG GMP_LIBRARY GMP_CPP_LIBRARY GMP_INC_DIR)

if (GMP_FOUND)
  set (GMP_LIBRARIES ${GMP_LIBRARY})
  set (GMP_INCLUDE_DIRS "${GMP_INC_DIR}")
  mark_as_advanced (GMP_DIR)
  if (NOT TARGET gmp::gmp)
    # For now we make the target global, because this file is included from a
    # CMakeLists.txt file in a subdirectory. With CMake >= 3.11, we could make
    # it global afterwards with
    # set_target_properties(gmp::gmp PROPERTIES IMPORTED_GLOBAL TRUE)
    add_library (gmp::gmp INTERFACE IMPORTED GLOBAL)
    set_target_properties (gmp::gmp PROPERTIES
              INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}"
              INTERFACE_LINK_LIBRARIES "${GMP_LIBRARIES};${GMP_CPP_LIBRARY}")
  endif()
endif()

mark_as_advanced(GMP_INC_DIR GMP_LIBRARY)
