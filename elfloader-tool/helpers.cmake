#
# Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

# Hook for CAmkES build system. This allows CAmkES projects to
# force a particular rootserver location.
function(SetElfloaderRootserversLast)
    set(ElfloaderRootserversLast ON CACHE BOOL "" FORCE)
endfunction()

# Hook for sel4test to effect shoehorn work.
function(SetElfloaderFudgeFactor FUDGE)
    set(ElfloaderFudgeFactor ${FUDGE} CACHE STRING "" FORCE)
endfunction()
