#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h> 
#include <time.h>
#include "utilities.h"

#define PCAP_MAGIC         0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

int debug = 0;

char* interface = NULL;
char* networkAddress = NULL;

void checkOptions(const int argc, char* argv[]);

int main(int argc, char *argv[])
{
    checkOptions(argc, argv);

    networkAddress = calculateNetworkAddress(interface, networkAddress, debug);
    trimInterface(interface, debug);

    int fd;
    do
    {
        fd = open(networkAddress, O_RDONLY);
        if (debug == 1)
        {
            fprintf(stdout, "open status: %d\n", fd);
        }
        if (fd == -1)
        {
            sleep(1);
        }
    } while (fd == -1);

    int headerSuccess = 0;
    do
    {
        if (debug == 1)
        {
            fprintf(stdout, "Reading pcap file header\n");
        }
        headerSuccess = readFileHeader(fd);
    } while (headerSuccess == 0);

    if (debug == 1)
    {
        fprintf(stdout, "Pcap file header read\n");
    }

    while(1 == 1)
    {
        readPacket(fd, debug);
        sleep(1);
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
                interface = MallocZ(sizeof(argv[i + 1] + 1)); // + 1 for null termination
                strcpy(interface, argv[i + 1]);
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