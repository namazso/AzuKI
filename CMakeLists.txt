# MIT License
#
# Copyright (c) namazso 2023
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VS_PLATFORM_TOOLSET "v143")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(AzuKI)

add_library(${PROJECT_NAME} SHARED
        library.cpp
        https.cpp
        tiny-json/tiny-json.c
        b64/encode.c
        b64/decode.c
        b64/buffer.c
        b64.cpp
        )

target_compile_definitions(${PROJECT_NAME} PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        )

target_link_libraries(${PROJECT_NAME} PRIVATE winhttp.lib)

target_link_options(${PROJECT_NAME} PRIVATE
        /BREPRO
        /DEPENDENTLOADFLAG:0x800
        /PDBALTPATH:%_PDB%
        /FILEALIGN:0x1000
        )

if ("${MSVC_C_ARCHITECTURE_ID}" STREQUAL "X86")
    target_link_options(${PROJECT_NAME} PRIVATE
            /EXPORT:AuthenticodeDigestSign=_AuthenticodeDigestSign@24
            )
endif ()
