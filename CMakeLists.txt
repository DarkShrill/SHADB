cmake_minimum_required(VERSION 3.14)
project(shadb C)

set(CMAKE_C_STANDARD 11)

add_executable(shadb main.c sha_file/sha1.c sha_file/sha1.h sha_file/sha-256.c sha_file/sha-256.h sha_file/sha-224.c sha_file/sha-224.h sha_file/common.c sha_file/common.h sha_file/sha-384.c sha_file/sha-384.h sha_file/sha-512.c sha_file/sha-512.h general.h general.c manager.c manager.h manage_sha.c manage_sha.h rwfile.c rwfile.h)