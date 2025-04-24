#include "utilities.h"
#include <time.h>
#include "arp.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h> 
#include <string.h>
#include <stdint.h> 
#include <sys/uio.h>

#define EPOCH_DIFF 2208988800UL

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
        \t\t1. print routing table upon change\n\
        \t\t2. print packet TTL messages\n\
        \t\t3. print UDP echo response messages\n\
        \t-r specify RIP second interval\n\
        \t-h: print options\n");
    exit(0);
}

void checkInterface(char* interface)
{
    if (interface == NULL)
    {
        fflush(stdout);
        fprintf(stderr, "Invalid interface: %s\n", interface);
        exit(1);
    }
}

static void printIPv4Header(const struct ipv4_header* header, char* interface) 
{
    fprintf(stdout, "Interface %s\n", interface);
    fprintf(stdout, "\tIPv4 Header:\n");
    fprintf(stdout, "\tVersion: %u\n", header->versionAndHeaderLength >> 4);
    fprintf(stdout, "\tHeader Length: %u bytes\n", (header->versionAndHeaderLength & 0x0F) * 4);
    fprintf(stdout, "\tType of Service: 0x%02X\n", header->typeOfService);
    fprintf(stdout, "\tTotal Length: %u\n", ntohs(header->totalLength));
    fprintf(stdout, "\tIdentification: %u\n", ntohs(header->identification));
    fprintf(stdout, "\tFrag Offset: %u\n", (ntohs(header->flagsAndFragmentOffset) & 0x1FFF) * 8);
    fprintf(stdout, "\tFrag DF: %s\n", (ntohs(header->flagsAndFragmentOffset) & 0x4000) >> 14 ? "yes" : "no");
    fprintf(stdout, "\tFrag MF: %s\n", (ntohs(header->flagsAndFragmentOffset) & 0x2000) >> 13 ? "yes" : "no");    
    fprintf(stdout, "\tTime to Live: %u\n", header->timeToLive);
    fprintf(stdout, "\tProtocol: %u\n", header->protocol);
    fprintf(stdout, "\tHeader Checksum: 0x%04X\n", header->headerChecksum);
    struct in_addr src, dst;
    src.s_addr = header->sourceIP;
    dst.s_addr = header->destinationIP;
    fprintf(stdout, "Source IP: %s\n", inet_ntoa(src));
    fprintf(stdout, "Destination IP: %s\n", inet_ntoa(dst));
}

static uint32_t ipStringToHostUint32(const char* ipString)
{
    struct in_addr addr;

    if (inet_pton(AF_INET, ipString, &addr) != 1) 
    {
        fflush(stdout);
        fprintf(stderr, "Invalid IP address: %s\n", ipString);
        exit(66);
    }

    return ntohl(addr.s_addr);
}

static uint16_t calculateChecksum(const struct ipv4_header* header, char* interface, const int debug) 
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
            // If there's an odd number of bytes, take the uint32_t netAddress;last byte and zero the second byte
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

    uint16_t retval = (uint16_t) checksum;
    retval = htons(retval);

    if (debug > 0)
    {
        fprintf(stdout, "interface %s, Calculated IPv4 Header Checksum: 0x%04X\n", interface, retval);
    }

    return retval;
}

static int verifyChecksum(const struct ipv4_header* header, char* interface, const int debug) 
{
    if (header->headerChecksum == 0)
    {
        return 1;
    }

    // Save the original checksum value
    uint16_t original_checksum = header->headerChecksum;

    // Set the checksum field to 0 to compute the checksum
    ((struct ipv4_header*)header)->headerChecksum = 0;

    // Compute the checksum
    uint16_t computed_checksum = calculateChecksum(header, interface, debug);

    // Restore the original checksum
    ((struct ipv4_header*)header)->headerChecksum = original_checksum;

    // Verify if the computed checksum matches the header checksum
    return (computed_checksum == original_checksum);
}

static uint16_t calculateUDPChecksum(struct udp_header* udp, struct ipv4_header* ip, const uint8_t* payload, size_t* payload_length, char* interface, const int debug) 
{

    struct udp_pseudo_header pseudo_hdr;
    pseudo_hdr.source_ip = ip->sourceIP;
    pseudo_hdr.dest_ip = ip->destinationIP;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.protocol = IPPROTO_UDP;
    pseudo_hdr.udp_length = udp->length;
    
    uint32_t checksum = 0;
    
    // Add pseudo-header
    uint16_t *ptr = (uint16_t *)&pseudo_hdr;
    for (size_t i = 0; i < sizeof(pseudo_hdr) / 2; i++) 
    {
        checksum += ntohs(ptr[i]);
    }
    
    // Add UDP header
    ptr = (uint16_t *)udp;
    for (size_t i = 0; i < sizeof(struct udp_header) / 2; i++) 
    {
        checksum += ntohs(ptr[i]);
    }
    
    // Add payload
    ptr = (uint16_t *)payload;
    *payload_length = udp->length - sizeof(struct udp_header);
    for (size_t i = 0; i < *payload_length / 2; i++) 
    {
        checksum += ntohs(ptr[i]);
    }

    if (*payload_length % 2) 
    {
        checksum += payload[*payload_length - 1] << 8;
    }
    
    // Handle overflow
    while (checksum >> 16) 
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    uint16_t retval = htonl((uint16_t)~checksum);

    if (debug > 0)
    {
        fprintf(stdout, "interface %s, Calculated UDP Header Checksum: 0x%04X\n", interface, retval);
    }
    
    return retval;
}

static int verifyUDPChecksum(struct udp_header* udp, struct ipv4_header* ip, const uint8_t* payload, size_t* payload_length, char* interface, const int debug) 
{
    return calculateUDPChecksum(udp, ip, payload, payload_length, interface, debug) == 0;
}

static uint16_t calculateICMPChecksum(struct icmp_header* icmp, const uint8_t* payload, size_t* payload_length, char* interface, const int debug) 
{
    uint32_t checksum = 0;
    
    // Add ICMP header
    uint16_t *ptr = (uint16_t *)icmp;
    for (size_t i = 0; i < sizeof(struct icmp_header) / 2; i++) 
    {
        checksum += ntohs(ptr[i]);
    }
    
    // Add payload
    ptr = (uint16_t *)payload;
    for (size_t i = 0; i < *payload_length / 2; i++) 
    {
        checksum += ntohs(ptr[i]);
    }
    
    if (*payload_length % 2) 
    {
        checksum += payload[*payload_length - 1] << 8;
    }
    
    // Handle overflow
    while (checksum >> 16) 
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    uint16_t retval = htons((uint16_t)~checksum);

    if (debug > 0)
    {
        fprintf(stdout, "interface %s, Calculated ICMP Header Checksum: 0x%04X\n", interface, retval);
    }
    
    return (retval);
}

static int verifyICMPChecksum(struct icmp_header* icmp, const uint8_t* payload, size_t payload_length, char* interface, const int debug) 
{
    if (icmp->checkSum == 0)
    {
        return 1;
    }

    uint16_t original_checksum = icmp->checkSum;
    icmp->checkSum = 0; // Set to zero for correct calculation

    // Compute the checksum over the ICMP header and payload
    uint16_t computed_checksum = calculateICMPChecksum(icmp, payload, &payload_length, interface, debug);

    // Restore the original checksum
    icmp->checkSum = original_checksum;

    // Check if the calculated checksum matches the original
    return (computed_checksum == original_checksum);
}

static uint32_t calculateBroadcastAddress(uint32_t netAddress, char* ipStr, uint8_t subnetLength, int debug)
{
    uint32_t host_bits = (1 << (32 - subnetLength)) - 1;
    uint32_t broadcastAddress = netAddress | htonl(host_bits);
    if (debug > 0)
    {
        fprintf(stdout, "Broadcast address for interface %s calculated as %s\n", ipStr, inet_ntoa(*(struct in_addr *)&broadcastAddress));
    }

    return broadcastAddress;
}

char** calculateNetworkBroadcastAndSubnetLength(char** addresses, char** networkAddresses, uint32_t* broadcastAddresses, uint8_t* subnetLengths, const unsigned count, const int debug)
{

    uint32_t netAddress;
    uint8_t subnetLength;

    for (unsigned i = 0; i < count; ++i)
    {
        char ipStr[INET_ADDRSTRLEN];
        char cidrStr[3]; // CIDR is max 2 digits + null terminator
        
        // Extract IP address and CIDR prefix using underscore `_`
        sscanf(addresses[i], "%[^_]_%s", ipStr, cidrStr);
        
        struct in_addr ipAddr, netmask, network;
        subnetLength = atoi(cidrStr); // Convert CIDR to integer for calculations
        subnetLengths[i] = subnetLength;

        // Convert IP address from string to binary
        if (inet_pton(AF_INET, ipStr, &ipAddr) != 1) 
        {
            fprintf(stderr, "Invalid IP address format.\n");
            exit(1);
        }
        netAddress = ipAddr.s_addr;
        broadcastAddresses[i] = calculateBroadcastAddress(netAddress, ipStr, subnetLength, debug);

        // Compute subnet mask from CIDR
        uint32_t mask = (subnetLength == 0) ? 0 : htonl(~((1 << (32 - subnetLength)) - 1));
        netmask.s_addr = mask;

        // Compute network address (IP & Subnet Mask)
        network.s_addr = ipAddr.s_addr & netmask.s_addr;

        // Convert network address back to string
        char netIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &network, netIP, INET_ADDRSTRLEN);

        // Write the final result into networkAddress
        sprintf(networkAddresses[i], "%s", netIP);

        if (debug > 0)
        {
            fprintf(stdout, "Network address for interface %s calculated as: %s/%hu\n\n", ipStr, networkAddresses[i], subnetLengths[i]);
        }
    }

    return networkAddresses;
}

void trimInterfaces(char** interfaces, const unsigned count, int debug)
{
    for (unsigned i = 0; i < count; ++i)
    {
        char* underscorePosition = strchr(interfaces[i], '_');
        if (underscorePosition != NULL)
        {
            *underscorePosition = '\0'; // Null-terminate at the underscore
        }
        if (debug > 0)
        {
            fprintf(stdout, "Interface trimmed to: %s\n", interfaces[i]);
        }
    }
}

// Expect host order ip address
static void ipStringFromUint32(char* buffer, uint32_t ipHostOrder)
{
    struct in_addr addr;
    addr.s_addr = htonl(ipHostOrder);  // Convert to network byte order

    if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) == NULL) 
    {
        perror("inet_ntop");
        exit(66);
    }
}

void printRouteTable(struct rip_entry** routeTable, const unsigned count)
{
    char ipString[INET_ADDRSTRLEN];
    char nextHopString[INET_ADDRSTRLEN];
    for (unsigned i = 0; i < count; ++i)
    {
        if (routeTable[i]->address != 0)
        {
            ipStringFromUint32(ipString, routeTable[i]->address);
            ipStringFromUint32(nextHopString, routeTable[i]->nextHop);
            fprintf(stdout, "Entry %u:\n", i);
            fprintf(stdout, "\taddress: %s\n", ipString);
            fprintf(stdout, "\tsubnet mask: %u\n", routeTable[i]->subnetMask);
            fprintf(stdout, "\tnext hop: %s\n", nextHopString);
            fprintf(stdout, "\tmetric: %u\n", routeTable[i]->metric);
        }
    }
}

void createDefaultRouteTable(struct rip_entry** routeTable, char** networkAddresses, uint8_t* subnetLengths, const unsigned interfaceCount, const unsigned routeCount, const int debug)
{
    for (unsigned i = 0; i < routeCount; ++i)
    {
        routeTable[i]->addressFamilyIdentifier = 2; // IP
        routeTable[i]->routeTag = 0;
        routeTable[i]->address = 0;
        routeTable[i]->subnetMask = 0;
        routeTable[i]->nextHop = 0;
        routeTable[i]->metric = 16;
        if (i < interfaceCount)
        {
            routeTable[i]->address = ipStringToHostUint32(networkAddresses[i]);
            routeTable[i]->subnetMask = subnetLengths[i];
            routeTable[i]->metric = 1;

            if (debug >= 1)
            {
                printRouteTable(routeTable, routeCount);
            }
        }
    }
}

int embedIPv4InMac(const char* IPv4, uint8_t** mac)
{
    struct in_addr ipv4;

    // Invalid ipv4 address
    fflush(stdout);
    if (inet_pton(AF_INET, IPv4, &ipv4) != 1)
    {
        return 0;
    }
    fflush(stdout);

    *mac[0] = 0x5E;
    *mac[1] = 0xFE;
    uint8_t* ip_bytes = (uint8_t *)&ipv4;
    *mac[2] = ip_bytes[0];
    *mac[3] = ip_bytes[1];
    *mac[4] = ip_bytes[2];
    *mac[5] = ip_bytes[3];

    return 1; // Success
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

void* readPacket(void* args)
{
    struct readPacketArguments* arguments = (struct readPacketArguments*)args;
    //int interfaceCount = arguments->count;
    int fd = arguments->fd;
    //int** fileDescriptors = arguments->fileDescriptors;
    char* interface = arguments->interface;
    //char** interfaces = arguments->interfaces;
    uint32_t broadcastAddress = arguments->broadcastAddress;
    uint8_t** mac = arguments->mac;
    int debug = arguments->debug;
    size_t* maximumPacketSize = arguments->maximumPacketSize;
    size_t* maximumPayloadSize = arguments->maximumPayloadSize;
    char* packetBuffer = arguments->packetBuffer;
    uint8_t* payload = arguments->payload;

    struct pcap_pkthdr pktHeader;
    int bytesRead = read(fd, &pktHeader, sizeof(pktHeader));
    if (bytesRead != sizeof(pktHeader))
    {
        if (bytesRead == -1)
        {
            perror("read");
            exit(66);
        }

        if (bytesRead == 0)
        {
            return NULL;
        }
        fflush(stdout);
        fprintf(stderr, "interface %s, Skipping truncated packet header: only %u bytes read\n", interface, bytesRead);
        return NULL;
    }
    
    if (debug > 1)
    {
        fprintf(stdout, "interface %s, Packet header read: %u bytes\n", interface, bytesRead);
    }

    if (*maximumPacketSize < pktHeader.caplen) // Resize needed
    {
        *maximumPacketSize = pktHeader.caplen;
        packetBuffer = ReallocZ(packetBuffer, *maximumPacketSize);
    }

    bytesRead = read(fd, packetBuffer, pktHeader.caplen);
    if (bytesRead != pktHeader.caplen)
    {
        fflush(stdout);
        fprintf(stderr, "interface %s, Skipping  truncated packet: only %u bytes read\n", interface, bytesRead);
        return NULL;
    }

    struct eth_hdr* eth = (struct eth_hdr*) packetBuffer;
    if (debug > 1)
    {
        fprintf(stdout, "interface %s, Ethernet header found, type: 0x%04x\n", interface, ntohs(eth->type));
    }

    if (ntohs(eth->type) == ETHERTYPE_ARP)
    {
        if (debug > 1)
        {
            fprintf(stdout, "interface %s, Ethernet protocol: ARP\n", interface);
        }
        
    }
    else if (ntohs(eth->type) == ETHERTYPE_IP)
    {
        if (debug > 1)
        {
            fprintf(stdout, "interface %s, Ethernet protocol: IP\n", interface);
        }
        

        struct ipv4_header* iph = (struct ipv4_header*) (packetBuffer + sizeof(struct eth_hdr));
    
        if (verifyChecksum(iph, interface, debug) == 0)
        {
            if (debug > 1)
            {
                fflush(stdout);
                fprintf(stderr, "interface %s, Header checksum invalid, rejecting packet\n", interface);
            }
            return NULL;
        }

        addArpEntry(iph->sourceIP, eth->sourceMACAddress);

        if (debug > 1)
        {
            printIPv4Header(iph, interface);
        } 
        
        char destination[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->destinationIP, destination, INET_ADDRSTRLEN);

        if (strcmp(destination, interface) == 0 || iph->destinationIP == broadcastAddress)
        {
            if (debug > 1)
            {
                fprintf(stdout, "Packet found for interface %s\n", interface);
            }

            size_t payloadLength;

            switch (iph->protocol)
            {
                case IPPROTO_ICMP:
                    if (debug > 0)
                    {
                        fprintf(stdout, "interface %s, IP protocol: ICMP\n", interface);
                    }
                    struct icmp_header* icmpHeader = (struct icmp_header*)(packetBuffer + sizeof(struct eth_hdr) + ((iph->versionAndHeaderLength & 0X0F) * 4));
                    uint16_t headerLength = (iph->versionAndHeaderLength & 0X0F) * 4;
                    payloadLength = ntohs(iph->totalLength) - headerLength - sizeof(struct icmp_header);
                    uint8_t* icmp_payload = (uint8_t*)(icmpHeader + 1); // Payload starts after the ICMP header

                    if (verifyICMPChecksum(icmpHeader, icmp_payload, payloadLength, interface, debug))
                    {
                        if (debug > 0)
                        {
                            fprintf(stdout, "interface %s, ICMP checksum verified, packet accepted\n", interface);
                        }
                        createPacket(fd, &pktHeader, eth, iph, icmpHeader, icmp_payload, &payloadLength, payload, maximumPayloadSize, mac, interface, debug);
                    }
                    else
                    {
                        if (debug > 1)
                        {
                            fprintf(stdout, "interface %s, ICMP checksum rejected, packet rejected\n", interface);
                        }
                    } 
                    break;
                case IPPROTO_UDP:
                    if (debug > 0)
                    {
                        fprintf(stdout, "interface %s, IP protocol: UDP\n", interface);
                    }
                    struct udp_header* udpHeader = (struct udp_header*)(packetBuffer + sizeof(struct eth_hdr) + ((iph->versionAndHeaderLength & 0X0F) * 4));
                    uint8_t* udpPayload = (uint8_t*)(udpHeader + 1);

                    if (verifyUDPChecksum(udpHeader, iph, udpPayload, &payloadLength, interface, debug))
                    {
                        if (debug > 0)
                        {
                            fprintf(stdout, "interface %s, UDP checksum verified, packet accepted\n", interface);
                        }
                        createPacket(fd, &pktHeader, eth, iph, udpHeader, udpPayload, &payloadLength, payload, maximumPayloadSize, mac, interface, debug);
                    }
                    else
                    {
                        if (debug > 0)
                        {
                            fprintf(stdout, "interface %s, UDP checksum rejected, packet rejected\n", interface);
                        }
                    }
                    break;
                default:
                    if (debug > 0)
                    {
                        fprintf(stdout, "interface %s, IP protocol: Unknown (%d)\n", interface, iph->protocol);
                    }
                    break;
            }
        }
    }
    return NULL;
}

void createPacket(const int fd, struct pcap_pkthdr* receivedPcapHeader, struct eth_hdr* receivedEthernetHeader, struct ipv4_header* receivedIPHeader, void* receivedProtocolHeader, uint8_t* receivedPayload, size_t* receivedPayloadLength, uint8_t* payload, size_t* maximumPayloadSize, uint8_t** mac, char* interface, const int debug)
{

    uint32_t remainingCaptureLength = receivedPcapHeader->caplen;

    struct eth_hdr responseEthernetHeader;

    responseEthernetHeader = createResponseEthernetHeader(receivedEthernetHeader, mac);
    remainingCaptureLength -= sizeof(struct eth_hdr);

    if (remainingCaptureLength > 0) // ipv4 header valid
    {
        switch (receivedIPHeader->protocol)
        {
            case IPPROTO_ICMP:
                if (debug > 0)
                {
                    fprintf(stdout, "interface %s, Creating response for ICMP packet\n", interface);
                }

                struct icmp_header responseICMPProtocolHeader = createResponseICMPHeader((struct icmp_header*) receivedProtocolHeader, receivedPayload, receivedPayloadLength, interface, debug);
                struct ipv4_header responseIPv4Header = createResponseIPv4Header(receivedIPHeader, receivedPayloadLength, interface, debug);

                struct pcap_pkthdr responsePcapHeader = createResponsePcapHeader(sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *receivedPayloadLength);
                sendPacket(fd, &responsePcapHeader, &responseEthernetHeader, &responseIPv4Header, &responseICMPProtocolHeader, receivedPayload, receivedPayloadLength, interface, debug);
                break;
            
            case IPPROTO_UDP:
                if (debug > 0)
                {
                    fprintf(stdout, "interface %s, Creating response for UDP packet\n", interface);
                }
                struct ipv4_header responseUDPIPv4Header = *receivedIPHeader;

                struct udp_header* receivedUDPHeader = (struct udp_header*)receivedProtocolHeader;
                struct udp_header responseUDPProtocolHeader;
                if (ntohs(receivedUDPHeader->destinationPort) == 37) // time
                {
                    time_t currentTime = time(NULL);
                    if (currentTime == ((time_t)-1)) return;
                    time_t total = currentTime + EPOCH_DIFF;
                    total = htonl(total);
                    *receivedPayloadLength = sizeof(time_t);
                    if (payload == NULL)
                    {
                        *maximumPayloadSize = *receivedPayloadLength;
                        payload = MallocZ(*receivedPayloadLength);
                    }
                    else if (*maximumPayloadSize < *receivedPayloadLength)
                    {
                        *maximumPayloadSize = *receivedPayloadLength;
                        payload = ReallocZ(payload, *receivedPayloadLength);
                    }
                    payload = memcpy(payload, &total, *receivedPayloadLength);

                    *receivedPayloadLength = htons(*receivedPayloadLength);

                    responseUDPIPv4Header.totalLength = sizeof(struct ipv4_header) + sizeof(struct udp_header) + *receivedPayloadLength;
                    responseUDPIPv4Header.totalLength = (htons(responseUDPIPv4Header.totalLength));

                    responseUDPProtocolHeader = createResponseUDPHeader((struct udp_header*) receivedProtocolHeader, payload, receivedPayloadLength, &responseUDPIPv4Header, interface, debug);

                    struct pcap_pkthdr responseUDPProtocolPcapHeader = createResponsePcapHeader(sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *receivedPayloadLength);
                    sendPacket(fd, &responseUDPProtocolPcapHeader, &responseEthernetHeader, &responseUDPIPv4Header, &responseUDPProtocolHeader, payload, receivedPayloadLength, interface, debug);
                    free(payload);
                }
                else // udp ping
                {
                    responseUDPIPv4Header.totalLength = sizeof(struct ipv4_header) + sizeof(struct udp_header) + *receivedPayloadLength;
                    
                    responseUDPProtocolHeader = createResponseUDPHeader((struct udp_header*) receivedProtocolHeader, receivedPayload, receivedPayloadLength, &responseUDPIPv4Header, interface, debug);
                    
                    struct pcap_pkthdr responseUDPProtocolPcapHeader = createResponsePcapHeader(sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *receivedPayloadLength);

                    sendPacket(fd, &responseUDPProtocolPcapHeader, &responseEthernetHeader, &responseUDPIPv4Header, &responseUDPProtocolHeader, receivedPayload, receivedPayloadLength, interface, debug);
                }
                break;
            
            default:
                fflush(stdout);
                fprintf(stderr, "interface %s, Create Packet: Unsupported Protocol\n", interface);
                break;
        }
    }

    else // Ethernet only packet (ARP)
    {

    }
}

struct eth_hdr createResponseEthernetHeader(struct eth_hdr* receivedEthernetHeader, uint8_t** mac)
{
    struct eth_hdr responseHeader;
    memcpy(&responseHeader.destinationMACAddress, receivedEthernetHeader->sourceMACAddress, sizeof(responseHeader.destinationMACAddress));
    for (unsigned i = 0; i < 6; ++i)
    {
        responseHeader.sourceMACAddress[i] = *mac[i];
    }
    responseHeader.type = receivedEthernetHeader->type;

    return responseHeader;
}

struct ipv4_header createResponseIPv4Header(struct ipv4_header* receivedIPHeader, size_t* payloadLength, char* interface, const int debug)
{
    struct ipv4_header responseIPv4Header;

    responseIPv4Header.versionAndHeaderLength = (4 << 4) | (sizeof(struct ipv4_header) / 4); // Version 4, header length in 32-bit words
    responseIPv4Header.typeOfService = 0x00;
    responseIPv4Header.totalLength = sizeof(struct ipv4_header) + *payloadLength;
    switch (receivedIPHeader->protocol)
    {
        case IPPROTO_ICMP:
            responseIPv4Header.totalLength += sizeof(struct icmp_header);
            break;
        
        case IPPROTO_UDP:
            responseIPv4Header.totalLength += sizeof(struct udp_header);
            break;

        default:
            fflush(stdout);
            fprintf(stderr, "Creating response ipv4 header for unsupported protocol");
            exit(1); // Not supported
    }
    responseIPv4Header.totalLength = htons(responseIPv4Header.totalLength);
    responseIPv4Header.identification = htons(rand() % 65536); // New ID for response
    responseIPv4Header.flagsAndFragmentOffset = htons(0x4000); // Don't Fragment
    responseIPv4Header.timeToLive = 64; // Reasonable default TTL
    responseIPv4Header.protocol = receivedIPHeader->protocol;
    responseIPv4Header.sourceIP = receivedIPHeader->destinationIP;
    responseIPv4Header.destinationIP = receivedIPHeader->sourceIP;
    responseIPv4Header.headerChecksum = 0; // Set to 0 before computing
    responseIPv4Header.headerChecksum = calculateChecksum(&responseIPv4Header, interface, debug);

    return responseIPv4Header;
}

struct icmp_header createResponseICMPHeader(struct icmp_header* receivedICMPHeader, uint8_t* payload, size_t* payloadLength, char* interface, const int debug)
{
    struct icmp_header responseICMPHeader;
    responseICMPHeader.type = 0;
    responseICMPHeader.code = 0;
    responseICMPHeader.checkSum = 0;
    responseICMPHeader.identifier = receivedICMPHeader->identifier;
    responseICMPHeader.sequenceNumber = receivedICMPHeader->sequenceNumber;

    responseICMPHeader.checkSum = calculateICMPChecksum(&responseICMPHeader, payload, payloadLength, interface, debug);

    return responseICMPHeader;
}

struct udp_header createResponseUDPHeader(struct udp_header* receivedUDPHeader, uint8_t* payload, size_t* payloadLength, struct ipv4_header* responseIPv4Header, char* interface, const int debug)
{
    // Received header is passed in for modification to be used for response
    responseIPv4Header->timeToLive = 64;
    uint32_t temp = responseIPv4Header->sourceIP;
    responseIPv4Header->sourceIP = responseIPv4Header->destinationIP;
    responseIPv4Header->destinationIP = temp;
    responseIPv4Header->headerChecksum = 0;
    responseIPv4Header->headerChecksum = calculateChecksum(responseIPv4Header, interface, debug);

    struct udp_header responseUDPHeader;
    responseUDPHeader.sourcePort = receivedUDPHeader->destinationPort;
    responseUDPHeader.destinationPort = receivedUDPHeader->sourcePort;
    responseUDPHeader.length = sizeof(struct udp_header) + *payloadLength;
    responseUDPHeader.checksum = 0;
    responseUDPHeader.checksum = calculateUDPChecksum(&responseUDPHeader, responseIPv4Header, payload, payloadLength, interface, debug);
    
    return responseUDPHeader;
}

uint8_t* createResponsePayload(uint8_t* receivedPayload)
{
    return NULL;
}

struct pcap_pkthdr createResponsePcapHeader(unsigned CapLen)
{
    struct pcap_pkthdr header;
    
    header.caplen = CapLen;
    header.len = CapLen;

    time_t now = time(NULL);

    header.ts_secs = (uint32_t)now;
    header.ts_usecs = (uint32_t)now * 1000000;

    return header;
}

void sendPacket(const int fd, struct pcap_pkthdr* pcapHeader, struct eth_hdr* ethernetHeader, struct ipv4_header* ipHeader, void* protocolHeader, uint8_t* payload, size_t* payloadLength, char* interface, const int debug)
{
    int success = -1;

    struct iovec iov[5];

    iov[0].iov_base = pcapHeader;
    iov[0].iov_len = sizeof(struct pcap_pkthdr);

    iov[1].iov_base = ethernetHeader;
    iov[1].iov_len = sizeof(struct eth_hdr);

    iov[2].iov_base = ipHeader;
    iov[2].iov_len = sizeof(struct ipv4_header);

    iov[3].iov_base = protocolHeader;
    iov[3].iov_len = sizeof(struct icmp_header);

    iov[4].iov_base = payload;
    iov[4].iov_len = *payloadLength;

    if (debug > 0)
    {
        fprintf(stdout, "interface %s, total length %u\n", interface, ipHeader->totalLength);
        fprintf(stdout, "interface %s, size: %lu\n", interface, sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *payloadLength);
        fprintf(stdout, "interface %s, payload size: %lu\n", interface, *payloadLength);
    }

    while (success == -1)
    {
        success = writev(fd, iov, 5);
    }
    if (debug > 0)
    {
        fprintf(stdout, "interface %s, SIZE ACTUALLY WRITTEN: %d\n", interface, success);
    }
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

void* ReallocZ(void* ptr, size_t nbytes)
{
    ptr = realloc(ptr, nbytes);
    if (ptr == NULL)
    {
        perror ("ReallocZ failed, fatal\n");
        exit(66);
    }

    return (ptr);
}