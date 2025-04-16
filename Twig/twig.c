#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h> 
#include <time.h>
#include <signal.h>
#include "utilities.h"

#define PCAP_MAGIC         0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

volatile sig_atomic_t keepRunning = 1;

int debug = 0;

int fd = -1;
char* interface = NULL;
char* networkAddress = NULL;

void checkOptions(const int argc, char* argv[]);

void freeVariablesAndClose();

void handleSigint(int sig);

void ensurePcapFileHeader(int fd);

int main(int argc, char *argv[])
{
    signal(SIGINT, handleSigint);

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    checkOptions(argc, argv);

    networkAddress = calculateNetworkAddress(interface, networkAddress, debug);
    trimInterface(interface, debug);

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    while (keepRunning == 1 && fd == -1)
    {
        fd = open(networkAddress, O_RDWR | O_APPEND | O_CREAT, 0660);
        if (debug == 1)
        {
            fprintf(stdout, "open status: %d\n", fd);
        }
        if (fd == -1)
        {
            nanosleep(&ts, NULL);
        }
    }

    if (keepRunning == 0)
    {
        freeVariablesAndClose();
        exit(0);
    }

    ensurePcapFileHeader(fd);

    int headerSuccess = 0;
    while (keepRunning == 1 && headerSuccess == 0)
    {
        if (debug == 1)
        {
            fprintf(stdout, "Reading pcap file header\n");
        }
        headerSuccess = readFileHeader(fd);
    }

    if (keepRunning == 0)
    {
        freeVariablesAndClose();
        exit(0);
    }

    if (debug == 1)
    {
        fprintf(stdout, "Pcap file header read\n");
    }

    while(keepRunning)
    {
        readPacket(fd, interface, debug);
        nanosleep(&ts, NULL);
    }

    freeVariablesAndClose();
    exit(0);

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

void freeVariablesAndClose()
{
    if (fd != -1)
    {
        close(fd);
    }
    if (interface != NULL)
    {
        free(interface);
        interface = NULL;
    }
    if (networkAddress != NULL)
    {
        free(networkAddress);
        networkAddress = NULL;
    }
    freePacketBufferAndPayload();
}

void handleSigint(int sig)
{
    (void)sig;
    fflush(stdout);
    fprintf(stdout, "Caught Ctrl+C. Quitting nicely...\n");
    keepRunning = 0;
}

void ensurePcapFileHeader(int fd)
{
    while (1)
    {
        struct pcap_file_header pfh;
        if (read(fd, &pfh, sizeof(struct pcap_file_header)) != sizeof(struct pcap_file_header)) // Empty file
        {
            pfh.magic = 0xa1b2c3d4;
            pfh.version_major = 2;
            pfh.version_minor = 4;
            pfh.thiszone = 0;
            pfh.sigfigs = 0;
            pfh.snaplen = 65535;
            pfh.linktype = 1;
            if (write(fd, &pfh, sizeof(pfh)) == sizeof(pfh))
            {
                lseek(fd, 0, SEEK_SET);
                return;
            }
            else lseek(fd, 0, SEEK_SET);
        }
    }
}