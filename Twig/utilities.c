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

// Pass in ethernet after reading from wire
static void ethernetNetworkToHost(struct eth_hdr* header)
{
    header->type = ntohs(header->type);
}

// Pass in ethernet before writing to wire
/*static void ethernetHostToNetwork(struct eth_hdr* header)
{
    header->type = htons(header->type);
}*/

// Pass in checksum after reading from wire
static void checksumNetworkToHost(struct ipv4_header* header)
{
    header->headerChecksum = ntohs(header->headerChecksum);
}

// Pass in checksum before writing to wire (after changing ipv4 from host to network order)
/*static void checsumHostToNetwork(struct ipv4_header* header)
{
    header->headerChecksum = htons(header->headerChecksum);
}*/

// Pass in ipv4 after reading from wire (only after verifying checksum)
static void ipv4NetworkToHost(struct ipv4_header* header) 
{
    header->totalLength = ntohs(header->totalLength);
    header->identification = ntohs(header->identification);
    header->flagsAndFragmentFragmentOffset = ntohs(header->flagsAndFragmentFragmentOffset);
}

// Pass in ipv4 before writing to wire (before calculating checksum)
/*static void ipv4HostToNetwork(struct ipv4_header* header)
{
    header->totalLength = htons(header->totalLength);
    header->identification = htons(header->identification);
    header->flagsAndFragmentFragmentOffset = htons(header->flagsAndFragmentFragmentOffset);
}*/


static void printIPv4Header(const struct ipv4_header* header) 
{
    fprintf(stdout, "IPv4 Header:\n");
    fprintf(stdout, "Version: %u\n", header->versionAndHeaderLength >> 4);
    fprintf(stdout, "Header Length: %u bytes\n", (header->versionAndHeaderLength & 0x0F) * 4);
    fprintf(stdout, "Type of Service: 0x%02X\n", header->typeOfService);
    fprintf(stdout, "Total Length: %u\n", header->totalLength);
    fprintf(stdout, "Identification: %u\n", header->identification);
    fprintf(stdout, "Frag Offset: %u\n", (header->flagsAndFragmentFragmentOffset & 0x1FFF) * 8);
    fprintf(stdout, "Frag DF: %s\n", (header->flagsAndFragmentFragmentOffset & 0x4000) >> 14 ? "yes" : "no");
    fprintf(stdout, "Frag MF: %s\n", (header->flagsAndFragmentFragmentOffset & 0x2000) >> 13 ? "yes" : "no");    
    fprintf(stdout, "Time to Live: %u\n", header->timeToLive);
    fprintf(stdout, "Protocol: %u\n", header->protocol);
    fprintf(stdout, "Header Checksum: 0x%04X\n", header->headerChecksum);
    struct in_addr src, dst;
    src.s_addr = header->sourceIP;
    dst.s_addr = header->destinationIP;
    fprintf(stdout, "Source IP: %s\n", inet_ntoa(src));
    fprintf(stdout, "Destination IP: %s\n", inet_ntoa(dst));
}

static uint16_t calculateChecksum(const struct ipv4_header* header) 
{
    uint32_t checksum = 0;
    const uint8_t* byte_ptr = (const uint8_t*)header;
    
    // Process each 16-bit chunk in the IP header
    for (size_t i = 0; i < sizeof(struct ipv4_header); i += 2) 
    {
        uint16_t word;
        
        // Read two bytes at a time (16 bits), ensuring proper byte order
        if (i + 1 < sizeof(struct ipv4_header)) 
        {
            word = (byte_ptr[i] << 8) | byte_ptr[i + 1];
        } else 
        {
            // If there's an odd number of bytes, take the last byte and zero the second byte
            word = byte_ptr[i] << 8;
        }

        // Add to the checksum
        checksum += word;

        // If there is an overflow, wrap it around (16-bit overflow handling)
        while (checksum > 0xFFFF) 
        {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }
    }

    // One's complement of the checksum
    checksum = ~checksum & 0xFFFF;

    return (uint16_t)checksum;
}

static int verifyChecksum(const struct ipv4_header* header, int debug) 
{
    // Save the original checksum value
    uint16_t original_checksum = header->headerChecksum;

    // Set the checksum field to 0 to compute the checksum
    ((struct ipv4_header*)header)->headerChecksum = 0;

    // Compute the checksum
    uint16_t computed_checksum = calculateChecksum(header);
    if (debug == 1)
    {
        fprintf(stdout, "Calculated Header Checksum: 0x%04X\n", computed_checksum);
    }

    // Restore the original checksum
    ((struct ipv4_header*)header)->headerChecksum = original_checksum;

    // Verify if the computed checksum matches the header checksum
    return (computed_checksum == original_checksum);
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

char* calculateNetworkAddress(const char* address, char* networkAddress, int debug) 
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

void readPacket(const int fd, char* interface, int debug)
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
    ethernetNetworkToHost(eth);
    if (debug == 1)
    {
        fprintf(stdout, "Ethernet header found, type: 0x%04x\n", eth->type);
    }

    struct ipv4_header* iph = (struct ipv4_header*) (packetBuffer + sizeof(struct eth_hdr));
    
    checksumNetworkToHost(iph);
    if (verifyChecksum(iph, debug) == 0)
    {
        if (debug == 1)
        {
            fflush(stdout);
            fprintf(stderr, "Header checksum invalid, rejecting packet\n");
        }
        return;
    }

    ipv4NetworkToHost(iph);

    if (debug == 1)
    {
        printIPv4Header(iph);
    } 
    
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