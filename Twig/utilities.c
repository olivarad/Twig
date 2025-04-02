#include "utilities.h"
#include "arp.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h> 

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

struct pcap_file_header 
{
	bpf_u_int32 magic;
	unsigned short version_major;
	unsigned short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction; this is always 0 */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps; this is always 0 */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr 
{
	bpf_u_int32 ts_secs;		/* time stamp */
	bpf_u_int32 ts_usecs;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};

struct eth_hdr 
{
	u_int8_t destinationMACAddress[6];
	u_int8_t sourceMACAddress[6];
	u_int16_t type;
 };

struct ipv4_header
{
	uint8_t versionAndHeaderLength;
	uint8_t typeOfService;
	uint16_t totalLength;
	uint16_t identification;
	uint16_t flagsAndFragmentFragmentOffset; // 1 bit reserved, 1 bit don't fragment, 1 bit more frgament, 13 bit fragment offset
	uint8_t timeToLive;
	uint8_t protocol;
	uint16_t headerChecksum;
	uint32_t sourceIP;
	uint32_t destinationIP;
};

uint32_t netAddress;
uint32_t broadcastAddress;
uint8_t subnetLength;

void printUsage(const char* program)
{
    fflush(stdout);
    fprintf(stderr,"Usage: %s -i <interface> (try 172.31.128.0_24)\n", program);
    exit(1);
}

void printHelp()
{
    fflush(stdout);
    fprintf(stdout, "Options:\n\
        \t-i: specify interface. ex: -i 172.31.128.0_24\n\
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

static void calculateBroadcastAddress(int debug)
{
    uint32_t host_bits = (1 << (32 - subnetLength)) - 1;
    broadcastAddress = netAddress | htonl(host_bits);
    if (debug == 1)
    {
        fprintf(stdout, "Broadcast address calculated as %s\n", inet_ntoa(*(struct in_addr *)&broadcastAddress));
    }
}

char* calculateNetworkAddress(const char *address, char *networkAddress, int debug) 
{
    char ipStr[INET_ADDRSTRLEN];
    char cidrStr[3]; // CIDR is max 2 digits + null terminator
    
    // Extract IP address and CIDR prefix using underscore `_`
    sscanf(address, "%[^_]_%s", ipStr, cidrStr);
    
    struct in_addr ipAddr, netmask, network;
    subnetLength = atoi(cidrStr); // Convert CIDR to integer for calculations

    // Convert IP address from string to binary
    if (inet_pton(AF_INET, ipStr, &ipAddr) != 1) 
    {
        fprintf(stderr, "Invalid IP address format.\n");
        exit(1);
    }
    netAddress = ipAddr.s_addr;
    calculateBroadcastAddress(debug);

    // Compute subnet mask from CIDR
    uint32_t mask = (subnetLength == 0) ? 0 : htonl(~((1 << (32 - subnetLength)) - 1));
    netmask.s_addr = mask;

    // Compute network address (IP & Subnet Mask)
    network.s_addr = ipAddr.s_addr & netmask.s_addr;

    // Convert network address back to string
    char netIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &network, netIP, INET_ADDRSTRLEN);

    // Write the final result into networkAddress
    networkAddress = MallocZ(INET_ADDRSTRLEN + 4);
    sprintf(networkAddress, "%s_%s.dmp", netIP, cidrStr);
    if (debug == 1)
    {
        fprintf(stdout, "Network address calculated as: %s\n", networkAddress);
    }
    return networkAddress;
}

void trimInterface(char* interface, int debug)
{
    char* underscorePosition = strchr(interface, '_');
    if (underscorePosition != NULL)
    {
        *underscorePosition = '\0'; // Null-terminate at the underscore
    }
    if (debug == 1)
    {
        fprintf(stdout, "Interface trimmed to: %s\n", interface);
    }
}



int readFileHeader(const int fd)
{
    struct pcap_file_header pfh;
    unsigned bytesRead = read(fd, &pfh, sizeof(pfh));
    if (bytesRead != sizeof(pfh))
    {
        /*fflush(stdout);
        fprintf(stderr, "Truncated pcap header: only %u bytes read\n", bytesRead);
        close(fd);
        exit(1);*/
        return 0;
    }

    if (pfh.magic != 0xa1b2c3d4)
    {
        fflush(stdout);
        fprintf(stderr, "Invalid magic number: 0x%08x\n", pfh.magic);
        exit(1);
    }
    return 1;
}

void readPacket(const int fd, int debug, char* interface)
{
    struct pcap_pkthdr pktHeader;
    int bytesRead = read(fd, &pktHeader, sizeof(pktHeader));
    if (bytesRead != sizeof(pktHeader))
    {
        if (bytesRead == 0)
        {
            return;
        }
        fflush(stdout);
        fprintf(stderr, "Truncated packet header: only %u bytes read\n", bytesRead);
        exit(1);
    }
    
    if (debug == 1)
    {
        fprintf(stdout, "Packet header read: %u bytes\n", bytesRead);
    }

    char* packetBuffer = MallocZ(pktHeader.caplen);
    bytesRead = read(fd, packetBuffer, pktHeader.caplen);
    if (bytesRead != pktHeader.caplen)
    {
        fflush(stdout);
        fprintf(stdout, "Truncated packet: only %u bytes read\n", bytesRead);
        exit(1);
    }

    struct eth_hdr* eth = (struct eth_hdr*) packetBuffer; // For ARP
    if (debug == 1)
    {
        fprintf(stdout, "Ethernet header found, type: %u\n", eth->type);
    }

    struct ipv4_header* iph = (struct ipv4_header*) (packetBuffer + sizeof(struct eth_hdr));
    
    char destinationBuffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->destinationIP, destinationBuffer, INET_ADDRSTRLEN);
    
    addArpEntry(iph->sourceIP, eth->sourceMACAddress);

    if (strcmp(destinationBuffer, interface) == 0 || iph->destinationIP == broadcastAddress)
    {
        if (debug == 1)
        {
            fprintf(stdout, "Packet found for me\n");
        }

        switch (iph->protocol)
        {
            case IPPROTO_ICMP:
                fprintf(stdout, "Protocol: ICMP\n");
                break;
            case IPPROTO_UDP:
                fprintf(stdout, "Protocol: UDP\n");
                break;
            case IPPROTO_TCP:
                fprintf(stdout, "Protoco: TCP\n");
                break;
            default:
                fprintf(stdout, "Protocol: Unknown (%d)\n", iph->protocol);
                break;
        }
    }

    free(packetBuffer);
}

void* MallocZ (int nbytes){
    char *ptr = malloc(nbytes);  // use the real routine
    if (ptr == NULL)
	{
	    perror ("MallocZ failed, fatal\n");
	    exit (66);
	}

	// initialize the space to all zeroes
    memset (ptr, '\00', nbytes);

    return (ptr);
}