#pragma once 
#include <stdint.h>

void printUsage(const char* program);

void printHelp();

void checkInterface(const char* interface);

char* calculateNetworkAddress(const char *address, char* networkAddress, int debug);

void trimInterface(char* interface, int debug);

int readFileHeader(const int fd);

void readPacket(const int fd, int debug, char* interface);

void* MallocZ (int nbytes);