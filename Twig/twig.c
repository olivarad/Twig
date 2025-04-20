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

int** fileDescriptors = NULL;
char** interfaces = NULL;
char** networkAddresses = NULL;
unsigned interfaceCount = 0;

void checkOptions(const int argc, char* argv[]);

void freeVariablesAndClose();

void handleSigint(int sig);

void ensurePcapFileHeader(int fd);

int main(int argc, char *argv[])
{
    signal(SIGINT, handleSigint);

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    checkOptions(argc, argv);

    networkAddresses = calculateNetworkAddresses(interfaces, networkAddresses, interfaceCount, debug);
    trimInterfaces(interfaces, interfaceCount, debug);

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    int notAllAssigned = 1;
    while (keepRunning == 1 && notAllAssigned == 1)
    {
        notAllAssigned = -1;
        for (unsigned i = 0; i < interfaceCount; ++i)
        {
            if (*fileDescriptors[i] != -1)
            {
                *fileDescriptors[i] = open(networkAddresses[i], O_RDWR | O_APPEND | O_CREAT, 0660);
                if (debug == 1)
                {
                    fprintf(stdout, "open status: %d\n", *fileDescriptors[i]);
                }
                if (*fileDescriptors[i] == -1)
                {
                    notAllAssigned = 1;                
                }
            }
        }
        if (notAllAssigned == 1)
        {
            nanosleep(&ts, NULL);
        }
    }

    if (keepRunning == 0)
    {
        freeVariablesAndClose();
        exit(0);
    }

    for (unsigned i = 0; i < interfaceCount; ++i)
    {
        ensurePcapFileHeader(*fileDescriptors[i]);
    }

    int headerSuccess = 0;
    while (keepRunning == 1 && headerSuccess == 0)
    {
        headerSuccess = 1;
        if (debug == 1)
        {
            fprintf(stdout, "Reading pcap file header\n");
        }
        
        for (unsigned i = 0; i < interfaceCount; ++i)
        {
            if (readFileHeader(*fileDescriptors[i]) == 0)
            {
                headerSuccess = 0;
            }
        }
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
        // TODO parallelize packet handling
        //readPacket(fd, interface, debug);
        nanosleep(&ts, NULL);
    }

    freeVariablesAndClose();
    exit(0);

}

void checkOptions(const int argc, char* argv[])
{
    if (argc != 1) // options selected - must at least specify interface
    {
        unsigned requestedInterfaceCount = 0;
        for (int i = 1; i < argc; ++i)
        {
            if (strcmp(argv[i], "-i") == 0) // define interface
            {
                if (i + 1 >= argc)
                {
                    printUsage(argv[0]);
                }
                else
                {
                    ++requestedInterfaceCount;
                    ++i;
                }
            }
        }

        printf("MEOW");
        fflush(stdout);

        interfaces = MallocZ(requestedInterfaceCount * sizeof(char*));
        for (unsigned i = 0; i < requestedInterfaceCount; ++i)
        {
            interfaces[i] = MallocZ(sizeof(char) * INET_ADDRSTRLEN);
            interfaces[i][0] = '\0';
        }

        networkAddresses = MallocZ(requestedInterfaceCount * sizeof(char*));
        for (unsigned i = 0; i < requestedInterfaceCount; ++i)
        {
            networkAddresses[i] = MallocZ(sizeof(char) * (INET_ADDRSTRLEN + 4));
            networkAddresses[i][0] = '\0';
        }
        
        fileDescriptors = MallocZ(requestedInterfaceCount * sizeof(int*));
        printf("MEOW");
        fflush(stdout);
        for (int i = 0; i < requestedInterfaceCount; ++i)
        {
            fileDescriptors[i] = MallocZ(sizeof(int));
            *fileDescriptors[i] = -1; // ensure assigned of not open
        }
        interfaceCount = requestedInterfaceCount;
        printf("MEOW");
        fflush(stdout);
        unsigned currentInterfaceIndex = 0;

        for (int i = 1; i < argc; ++i)
        {
            if (strcmp(argv[i], "-i") == 0) // define interface
            {
                if (i + 1 >= argc) // Reset or no interface specified
                {
                    printUsage(argv[0]);
                }

                for (int j = 0; i < interfaceCount; ++j)
                {
                    if (interfaces[j] != NULL && strcpy(argv[i + 1], interfaces[j]))
                    {
                        fflush(stdout);
                        fprintf(stderr, "Reassignedment of interface: %s, exiting.", interfaces[j]);
                        exit(66);
                    }
                }

                strcpy(interfaces[currentInterfaceIndex++], argv[i + 1]);
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

    for (unsigned i = 0; i < interfaceCount; ++i)
    {
        checkInterface(interfaces[i]);

        if (debug == 1)
        {
            fprintf(stdout, "debug enabled\n");
            fprintf(stdout, "interface: %s\n", interfaces[i]);
        }
    }
}

void freeVariablesAndClose()
{
    for (unsigned i = 0; i < interfaceCount; ++i)
    {
        if (fileDescriptors[i] != NULL)
        {
            if (*fileDescriptors[i] != -1)
            {
                close(*fileDescriptors[i]);
            }
            free(fileDescriptors[i]);
            fileDescriptors[i] = NULL;
        }

        if (interfaces[i] != NULL)
        {
            free(interfaces[i]);
            interfaces[i] = NULL;
        }
        
        if (networkAddresses[i] != NULL)
        {
            free(networkAddresses[i]);
            networkAddresses[i] = NULL;
        }
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
    uint8_t buf[24];

    if (read(fd, buf, sizeof(buf)) != sizeof(buf)) 
    {
        uint32_t magic = 0xa1b2c3d4;
        uint16_t ver_major = 2;
        uint16_t ver_minor = 4;
        int32_t  thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 10000;
        uint32_t linktype = 1;

        memcpy(buf + 0,  &magic, sizeof(bpf_u_int32));
        memcpy(buf + 4,  &ver_major, sizeof(unsigned short));
        memcpy(buf + 6,  &ver_minor, sizeof(unsigned short));
        memcpy(buf + 8,  &thiszone,  sizeof(bpf_int32));
        memcpy(buf + 12, &sigfigs,   sizeof(bpf_u_int32));
        memcpy(buf + 16, &snaplen,   sizeof(bpf_u_int32));
        memcpy(buf + 20, &linktype,  sizeof(bpf_u_int32));

        lseek(fd, 0, SEEK_SET);
        if (write(fd, buf, sizeof(buf)) != sizeof(buf)) 
        {
            exit(66);
        }
    }
    lseek(fd, 0, SEEK_SET);
    if (debug == 1)
    {
        uint8_t check[24];
        read(fd, check, sizeof(check));
            fprintf(stdout, "PCAP file header:\n");
        for (int i = 0; i < 24; i++) 
        {
            fprintf(stdout, "%02x ", check[i]);
        }
        fprintf(stdout, "\n");
        lseek(fd, 0, SEEK_SET);
    }
}