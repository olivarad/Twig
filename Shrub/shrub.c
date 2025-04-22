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
#include <pthread.h>
#include "utilities.h"

#define PCAP_MAGIC         0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

volatile sig_atomic_t keepRunning = 1;

unsigned debug = 0;

int** fileDescriptors = NULL;
char** interfaces = NULL;
char** networkAddresses = NULL;
uint32_t* broadcastAddresses = NULL;
char* defaultRoute = NULL;
struct readPacketArguments** threadArguments = NULL;
unsigned interfaceCount = 0;
int RIPInterval = 30;


void checkOptions(const int argc, char* argv[]);

void freeVariablesAndClose();

void handleSigint(int sig);

void ensurePcapFileHeader(int fd);

int main(int argc, char *argv[])
{
    signal(SIGINT, handleSigint);

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    checkOptions(argc, argv);

    networkAddresses = calculateNetworkAndBroadcastAddresses(interfaces, networkAddresses, broadcastAddresses, interfaceCount, debug);
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
            if (*fileDescriptors[i] == -1)
            {
                *fileDescriptors[i] = open(networkAddresses[i], O_RDWR | O_APPEND | O_CREAT, 0660);
                if (debug > 0)
                {
                    fprintf(stdout, "open status: %d for network address %s\n", *fileDescriptors[i], networkAddresses[i]);
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

    if (debug > 0)
    {
        fprintf(stdout, "\n");
    }

    threadArguments = MallocZ(sizeof(struct readPacketArguments*) * interfaceCount);
    for (unsigned i = 0; i < interfaceCount; ++i)
    {
        threadArguments[i] = MallocZ (sizeof(struct readPacketArguments));
        threadArguments[i]->fd = *fileDescriptors[i];
        threadArguments[i]->interface = interfaces[i];
        threadArguments[i]->broadcastAddress = broadcastAddresses[i];
        
        threadArguments[i]->mac = MallocZ(sizeof(uint8_t*) * 6);
        for (unsigned j = 0; j < 6; ++j)
        {
            threadArguments[i]->mac[j] = MallocZ(1);
        }
        if (embedIPv4InMac(threadArguments[i]->interface, threadArguments[i]->mac) != 1)
        {
            fflush(stdout);
            fprintf(stderr, "Invalid interface: %s\n", threadArguments[i]->interface);
            freeVariablesAndClose();
            exit(66);
        }

        threadArguments[i]->debug = debug;
        threadArguments[i]->maximumPacketSize = MallocZ(sizeof(size_t));
        *threadArguments[i]->maximumPacketSize = 1500;
        threadArguments[i]->maximumPayloadSize = MallocZ(sizeof(size_t));
        *threadArguments[i]->maximumPayloadSize = 0;
        threadArguments[i]->packetBuffer = MallocZ(1500);
        threadArguments[i]->payload = NULL;
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

    if (debug > 0)
    {
        fprintf(stdout, "\n");
    }

    int successes[interfaceCount];
    for (unsigned i = 0; i < interfaceCount; ++i)
    successes[i] = 0;
    int headerSuccess = 0;
    
    do
    {
        headerSuccess = 1;
        
        for (unsigned i = 0; i < interfaceCount; ++i)
        {
            if (successes[i] == 0 && readFileHeader(*fileDescriptors[i]) == 0)
            {
                headerSuccess = 0;
            }
            else
            {
                successes[i] = 1;
            }
        }
    } while (keepRunning == 1 && headerSuccess == 0);

    if (keepRunning == 0)
    {
        freeVariablesAndClose();
        exit(0);
    }

    pthread_t threads[interfaceCount];

    while(keepRunning)
    {
        for (unsigned i = 0; i < interfaceCount; ++i)
        {
            pthread_create(&threads[i], NULL, readPacket, threadArguments[i]);
        }

        for (unsigned i = 0; i < interfaceCount; ++i)
        {
            pthread_join(threads[i], NULL);
        }
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

        broadcastAddresses = MallocZ(requestedInterfaceCount * sizeof(uint32_t));
        
        fileDescriptors = MallocZ(requestedInterfaceCount * sizeof(int*));
        for (int i = 0; i < requestedInterfaceCount; ++i)
        {
            fileDescriptors[i] = MallocZ(sizeof(int));
            *fileDescriptors[i] = -1; // ensure assigned of not open
        }
        interfaceCount = requestedInterfaceCount;
        unsigned currentInterfaceIndex = 0;

        for (int i = 1; i < argc; ++i)
        {
            if (strcmp(argv[i], "-i") == 0) // define interface
            {
                if (i + 1 >= argc) // Reset or no interface specified
                {
                    printUsage(argv[0]);
                }
                else
                {
                    for (int j = 0; j < interfaceCount; ++j)
                    {
                        if (interfaces[j] != NULL && strcmp(argv[i + 1], interfaces[j]) == 0)
                        {
                            fflush(stdout);
                            fprintf(stderr, "Reassignment of interface: %s, exiting.", interfaces[j]);
                            exit(66);
                        }
                    }
                }

                strcpy(interfaces[currentInterfaceIndex++], argv[i + 1]);
                ++i; // Skip assigned interface
                continue;
            }
            else if (strcmp(argv[i], "-d") == 0) // increment debug level
            {
                ++debug;
            }
            else if (strcmp(argv[i], "-h") == 0) // help
            {
                printHelp();
            }
            else if (strcmp(argv[i], "--default-route"))
            {
                if (i + 1 >= argc || interfaceCount < 2) // Reset, no interface specified, or default interface specification not allowed (host)
                {
                    printUsage(argv[0]);
                }

                else
                {
                    // Default route specification allowed
                    if (defaultRoute == NULL)
                    {
                        if (i + 1 >= argc)
                        {
                            // Default route specified to no value
                            printUsage(argv[0]);
                        }
                        defaultRoute = MallocZ(INET_ADDRSTRLEN + 1); // +1 for null termination
                        strcpy(defaultRoute, argv[i + 1]);
                        ++i;
                    }
                    else
                    {
                        fflush(stdout);
                        fprintf(stderr, "Error: default route re-specified, exiting");
                        printUsage(argv[0]);
                    }
                }
            }
            else if (strcmp(argv[i], "-r"))
            {
                if (i + 1 >= argc)
                {
                    printUsage(argv[0]);
                }
                else
                {
                    RIPInterval = atoi(argv[i + 1]);
                    if (RIPInterval <= 0)
                    {
                        fflush(stdout);
                        fprintf(stderr, "Error: invalid RIP interval - %s, exiting\n", argv[i + 1]);
                        exit(66);
                    }
                    ++i;
                }
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

    if (debug > 0)
    {
        fprintf(stdout, "debug level %u enabled\n", debug);
        fprintf(stdout, "enabled debug options:\n");
        if (debug >= 1)
        {
            fprintf(stdout, "\t-Routing table changes will print entire routing table\n");
        }
        if (debug >= 2)
        {
            fprintf(stdout, "\t-TTL expired messages enabled\n");
        }
        if (debug >= 3)
        {
            fprintf(stdout, "\t-UDP echo response generation status messages enabled\n");
        }
    }

    if (debug > 0)
    fprintf(stdout, "\nInterfaces:\n");

    for (unsigned i = 0; i < interfaceCount; ++i)
    {
        checkInterface(interfaces[i]);

        if (debug > 0)
        {
            fprintf(stdout, "\t%s\n", interfaces[i]);
        }
    }
    if (debug > 0)
    {
        fprintf(stdout, "\n");
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

    fileDescriptors = NULL;
    interfaces = NULL;
    networkAddresses = NULL;
    broadcastAddresses = NULL;

    if (threadArguments != NULL)
    {
        for (unsigned i = 0; i < interfaceCount; ++i)
        {
            if (threadArguments[i] != NULL)
            {
                if (threadArguments[i]->mac != NULL)
                {
                    for (unsigned j = 0; j < 6; ++j)
                    {
                        if (threadArguments[i]->mac[j] != NULL)
                        {
                            free(threadArguments[i]->mac[j]);
                            threadArguments[i]->mac[j] = NULL;
                        }
                    }
                    free(threadArguments[i]->mac);
                    threadArguments[i]->mac = NULL;
                }

                if (threadArguments[i]->packetBuffer != NULL)
                {
                    free(threadArguments[i]->packetBuffer);
                    threadArguments[i]->packetBuffer = NULL;
                }
                if (threadArguments[i]->maximumPacketSize != NULL)
                {
                    free(threadArguments[i]->maximumPacketSize);
                    threadArguments[i]->maximumPacketSize = NULL;
                }
                if (threadArguments[i]->maximumPayloadSize != NULL)
                {
                    free(threadArguments[i]->maximumPayloadSize);
                    threadArguments[i]->maximumPayloadSize = NULL;
                }
                free(threadArguments[i]);
                threadArguments[i] = NULL;
            }
        }
        free(threadArguments);
        threadArguments = NULL;
    }

    if (defaultRoute != NULL)
    {
        free(defaultRoute);
        defaultRoute = NULL;
    }
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
    if (debug > 0)
    {
        uint8_t check[24];
        read(fd, check, sizeof(check));
            fprintf(stdout, "PCAP file header for fd %d:\n\t", fd);
        for (int i = 0; i < 24; i++) 
        {
            fprintf(stdout, "%02x ", check[i]);
        }
        fprintf(stdout, "\n");
        lseek(fd, 0, SEEK_SET);
    }
}