cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ollama_honeypot LANGUAGES CXX)

find_program(CCACHE_EXECUTABLE ccache)

if(CCACHE_EXECUTABLE)
    message(STATUS "Ccache found: ${CCACHE_EXECUTABLE}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXECUTABLE}" CACHE STRING "Compiler launcher for C++")
else()
    message(STATUS "Ccache not found. Build will not use Ccache. (Install ccache for faster rebuilds)")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/cpm.cmake)

find_package(Threads REQUIRED)

CPMAddPackage(
        NAME nlohmann_json
        GITHUB_REPOSITORY nlohmann/json
        VERSION 3.11.3
)

CPMAddPackage(
        NAME fmt
        GITHUB_REPOSITORY fmtlib/fmt
        GIT_TAG 11.0.2
)

CPMAddPackage(
        NAME spdlog
        GITHUB_REPOSITORY gabime/spdlog
        GIT_TAG v1.14.1
        OPTIONS
        "SPDLOG_FMT_EXTERNAL ON"
        "SPDLOG_BUILD_EXAMPLE OFF"
        "SPDLOG_BUILD_TESTS OFF"
        "SPDLOG_BUILD_BENCH OFF"
)

CPMAddPackage(
        NAME Asio
        GITHUB_REPOSITORY chriskohlhoff/asio
        GIT_TAG asio-1-30-2
        OPTIONS
        "ASIO_ENABLE_BUFFER_DEBUGGING OFF"
        "ASIO_BUILD_TESTS OFF"
        "ASIO_BUILD_EXAMPLES OFF"
)

CPMAddPackage("gh:Tessil/robin-map@1.4.0")

if(Asio_ADDED)
    message(STATUS "Manually configuring Asio target 'asio::asio'")

    add_library(asio::asio INTERFACE IMPORTED GLOBAL)

    target_include_directories(asio::asio SYSTEM INTERFACE
            "${Asio_SOURCE_DIR}/asio/include"
    )

    target_compile_definitions(asio::asio INTERFACE
            ASIO_STANDALONE
    )

    target_link_libraries(asio::asio INTERFACE Threads::Threads)

    if(WIN32)
        macro(get_win32_winnt version)
            if(CMAKE_SYSTEM_VERSION)
                set(ver ${CMAKE_SYSTEM_VERSION})
                string(REGEX MATCH "^([0-9]+).([0-9])" ver ${ver})
                string(REGEX MATCH "^([0-9]+)" verMajor ${ver})
                if("${verMajor}" MATCHES "10")
                    set(verMajor "A")
                    string(REGEX REPLACE "^([0-9]+)" ${verMajor} ver ${ver})
                endif()
                string(REPLACE "." "" ver ${ver})
                string(REGEX REPLACE "([0-9A-Z])" "0\\1" ver ${ver})
                set(${version} "0x${ver}")
            else()
                set(${version} "0x0A00")
            endif()
        endmacro()

        if(NOT DEFINED _WIN32_WINNT)
            get_win32_winnt(ver)
            set(_WIN32_WINNT ${ver})
        endif()
        message(STATUS "Setting _WIN32_WINNT=${_WIN32_WINNT} for Asio")

        target_compile_definitions(asio::asio INTERFACE
                _WIN32_WINNT=${_WIN32_WINNT}
                WIN32_LEAN_AND_MEAN
        )
    endif()

    message(STATUS "Asio target 'asio::asio' configured successfully.")

else()
    message(FATAL_ERROR "CPM failed to add Asio dependency. Cannot configure target.")
endif()

CPMAddPackage(
        NAME Crow
        GITHUB_REPOSITORY CrowCpp/crow
        VERSION 1.2.1
        OPTIONS
)

add_subdirectory(src)