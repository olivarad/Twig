#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h> 
#include "utilities.h"

#define PCAP_MAGIC         0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

int debug = 0;

char* interface = NULL;

void checkOptions(const int argc, char* argv[]);

int main(int argc, char *argv[])
{
    checkOptions(argc, argv);

    int fd;
    do
    {
        fd = open(interface, O_RDONLY);
        if (debug == 1)
        {
            fprintf(stdout, "open status: %d\n", fd);
        }
    } while (fd == -1);

    int headerSuccess = 0;
    do
    {
        if (debug == 1)
        {
            fprintf(stdout, "Reading header\n");
        }
        headerSuccess = readHeader(fd);
    } while (headerSuccess == 0);

    if (debug == 1)
    {
        fprintf(stdout, "Header read\n");
    }

    while(1 == 1)
    {
        readPacket(fd);
    }
}

void checkOptions(const int argc, char* argv[])
{
    if (argc != 1) // options selected - must at least specify interface
    {
        for (int i = 1; i < argc; ++i)
        {
            if (strcmp(argv[i], "-i") == 0) // define interface
            {
                if (interface != NULL || i + 1 >= argc) // Reset or no interface specified
                {
                    printUsage(argv[0]);
                }
                interface = MallocZ(sizeof(argv[i + 1] + 4 + 1)); // + 4 for .dmp + 1 for null termination
                strcpy(interface, argv[i + 1]);
                strcat(interface, ".dmp");
                ++i; // Skip assigned interface
            }
            else if (strcmp(argv[i], "-d") == 0) // enable debugging
            {
                if (debug == 1) // Cannot set multiple times
                {
                    printUsage(argv[0]);
                }
                debug = 1;
            }
            else if (strcmp(argv[i], "-h") == 0) // help
            {
                printHelp();
            }
            else // invalid option, print usage
            {
                printUsage(argv[0]);
            }
        }
    }
    else
    {
        printUsage(argv[0]);
    }

    checkInterface(interface);

    if (debug == 1)
    {
        fprintf(stdout, "debug enabled\n");
        fprintf(stdout, "interface: %s\n", interface);
    }
}