#pragma once 
#include <stdint.h>

void printUsage(const char* program);

void printHelp();

void checkInterface(const char* interface);

int readHeader(const int fd);

void readPacket(const int fd);

void* MallocZ (int nbytes);