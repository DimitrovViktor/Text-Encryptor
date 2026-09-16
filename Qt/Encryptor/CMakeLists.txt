cmake_minimum_required(VERSION 3.16)
project(encryptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(encryptor
    main.cpp
    encryptor.cpp
    encryptor.h
    encryptor.ui
)

target_include_directories(encryptor PRIVATE ${CMAKE_SOURCE_DIR})

target_link_libraries(encryptor PRIVATE
    Qt6::Widgets
    ${CMAKE_SOURCE_DIR}/sodium/libsodium.lib
    ${CMAKE_SOURCE_DIR}/argon/Argon2OptDll.lib
)
