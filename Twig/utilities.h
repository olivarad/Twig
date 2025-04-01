#pragma once 
#include <stdint.h>

void printUsage(const char* program);

void printHelp();

void checkInterface(const char* interface);

char* calculate_network_address(const char *address, char* networkAddress, int debug);

int readFileHeader(const int fd);

void readPacket(const int fd, int debug);

void* MallocZ (int nbytes);