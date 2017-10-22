cmake_minimum_required (VERSION 3.2)
project (cli-launcher)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include (CTest)
enable_testing()

find_package(
    Boost
    COMPONENTS
        filesystem
        regex
        log_setup
        log
        chrono
        date_time
        system
        program_options
    REQUIRED
)

find_package(OpenSSL REQUIRED)

add_definitions(-DBOOST_LOG_DYN_LINK)

include_directories(${Boost_INCLUDE_DIRS})

set(SOURCES main.cpp)

add_executable(cli-launcher cli-launcher)

target_link_libraries(cli-launcher ${Boost_LIBRARIES})
