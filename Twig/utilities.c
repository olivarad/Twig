#include <stdio.h>
#include <stdlib.h>

void printUsage(const char* program)
{
    fflush(stdout);
    fprintf(stderr,"Usage: %s -i <interface> (try 172.31.128.2_24)\n", program);
    exit(1);
}

void printHelp()
{
    fflush(stdout);
    fprintf(stdout, "Options:\n\
        \t-i: specify interface. ex: -i 172.31.128.2_24\n\
        \t-d: enable debugging\n\
        \t-h: print options\n");
    exit(0);
}

void checkInterface(const char* interface)
{
    if (interface == NULL)
    {
        fflush(stdout);
        fprintf(stderr, "Invalid interface: %s\n", interface);
        exit(1);
    }
}