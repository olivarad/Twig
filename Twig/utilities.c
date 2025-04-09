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

size_t maximumPacketSize = 1500;
size_t maximumPayloadSize = 0;

char* packetBuffer = NULL;
uint8_t* payload = NULL;

uint32_t netAddress;
uint32_t broadcastAddress;
uint8_t subnetLength;

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

static void printIPv4Header(const struct ipv4_header* header) 
{
    fprintf(stdout, "IPv4 Header:\n");
    fprintf(stdout, "Version: %u\n", header->versionAndHeaderLength >> 4);
    fprintf(stdout, "Header Length: %u bytes\n", (header->versionAndHeaderLength & 0x0F) * 4);
    fprintf(stdout, "Type of Service: 0x%02X\n", header->typeOfService);
    fprintf(stdout, "Total Length: %u\n", ntohs(header->totalLength));
    fprintf(stdout, "Identification: %u\n", ntohs(header->identification));
    fprintf(stdout, "Frag Offset: %u\n", (ntohs(header->flagsAndFragmentOffset) & 0x1FFF) * 8);
    fprintf(stdout, "Frag DF: %s\n", (ntohs(header->flagsAndFragmentOffset) & 0x4000) >> 14 ? "yes" : "no");
    fprintf(stdout, "Frag MF: %s\n", (ntohs(header->flagsAndFragmentOffset) & 0x2000) >> 13 ? "yes" : "no");    
    fprintf(stdout, "Time to Live: %u\n", header->timeToLive);
    fprintf(stdout, "Protocol: %u\n", header->protocol);
    fprintf(stdout, "Header Checksum: 0x%04X\n", header->headerChecksum);
    struct in_addr src, dst;
    src.s_addr = header->sourceIP;
    dst.s_addr = header->destinationIP;
    fprintf(stdout, "Source IP: %s\n", inet_ntoa(src));
    fprintf(stdout, "Destination IP: %s\n", inet_ntoa(dst));
}

static uint16_t calculateChecksum(const struct ipv4_header* header, const int debug) 
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

    uint16_t retval = (uint16_t) checksum;

    if (debug == 1)
    {
        fprintf(stdout, "Calculated IPv4 Header Checksum: 0x%04X\n", retval);
    }

    return retval;
}

static int verifyChecksum(const struct ipv4_header* header, const int debug) 
{
    // Save the original checksum value
    uint16_t original_checksum = ntohs(header->headerChecksum);

    // Set the checksum field to 0 to compute the checksum
    ((struct ipv4_header*)header)->headerChecksum = 0;

    // Compute the checksum
    uint16_t computed_checksum = calculateChecksum(header, debug);

    // Restore the original checksum
    ((struct ipv4_header*)header)->headerChecksum = original_checksum;

    // Verify if the computed checksum matches the header checksum
    return (computed_checksum == original_checksum);
}

static uint16_t calculateUDPChecksum(struct udp_header* udp, struct ipv4_header* ip, const uint8_t* payload, size_t* payload_length, const int debug) 
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

    uint16_t retval = ((uint16_t)~checksum);

    if (debug == 1)
    {
        fprintf(stdout, "Calculated UDP Header Checksum: 0x%04X\n", retval);
    }
    
    return htonl(retval);
}

static int verifyUDPChecksum(struct udp_header* udp, struct ipv4_header* ip, const uint8_t* payload, size_t* payload_length, const int debug) 
{
    return calculateUDPChecksum(udp, ip, payload, payload_length, debug) == 0;
}

static uint16_t calculateTCPChecksum(struct tcp_header* tcp, struct ipv4_header* ip, const uint8_t* payload, size_t* payload_length, const int debug) 
{

    struct tcp_pseudo_header pseudo_hdr;
    pseudo_hdr.source_ip = ip->sourceIP;
    pseudo_hdr.dest_ip = ip->destinationIP;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_length = ip->totalLength - ((ip->versionAndHeaderLength & 0x0F) * 4);
    
    uint32_t checksum = 0;
    
    // Add pseudo-header
    uint16_t *ptr = (uint16_t *)&pseudo_hdr;
    for (size_t i = 0; i < sizeof(pseudo_hdr) / 2; i++) 
    {
        checksum += ntohs(ptr[i]);
    }
    
    // Add TCP header
    ptr = (uint16_t *)tcp;
    for (size_t i = 0; i < sizeof(struct tcp_header) / 2; i++) 
    {
        checksum += ntohs(ptr[i]);
    }
    
    // Add payload
    ptr = (uint16_t *)payload;
    *payload_length = pseudo_hdr.tcp_length - ((tcp->dataOffset >> 4) * 4);
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

    uint16_t retval = ((uint16_t)~checksum);

    if (debug == 1)
    {
        fprintf(stdout, "Calculated TCP Header Checksum: 0x%04X\n", retval);
    }
    
    return htonl(retval);
}

static int verifyTCPChecksum(struct tcp_header* tcp, struct ipv4_header* ip, const uint8_t* payload, size_t* payload_length, const int debug) 
{
    return calculateTCPChecksum(tcp, ip, payload, payload_length, debug) == 0;
}

static uint16_t calculateICMPChecksum(struct icmp_header* icmp, const uint8_t* payload, size_t* payload_length, const int debug) 
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
    
    uint16_t retval = ((uint16_t)~checksum);

    if (debug == 1)
    {
        fprintf(stdout, "Calculated ICMP Header Checksum: 0x%04X\n", retval);
    }
    
    return htonl(retval);
}

static int verifyICMPChecksum(struct icmp_header* icmp, const uint8_t* payload, size_t payload_length, const int debug) 
{
    uint16_t original_checksum = icmp->checkSum;
    icmp->checkSum = 0; // Set to zero for correct calculation

    // Compute the checksum over the ICMP header and payload
    uint16_t computed_checksum = calculateICMPChecksum(icmp, payload, &payload_length, debug);

    // Restore the original checksum
    icmp->checkSum = original_checksum;

    // Check if the calculated checksum matches the original
    return (computed_checksum == 0);
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

    packetBuffer = MallocZ(maximumPacketSize);

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
        fprintf(stderr, "Skipping truncated packet header: only %u bytes read\n", bytesRead);
        return;
    }
    
    if (debug == 1)
    {
        fprintf(stdout, "Packet header read: %u bytes\n", bytesRead);
    }

    if (maximumPacketSize < pktHeader.caplen) // Resize needed
    {
        maximumPacketSize = pktHeader.caplen;
        packetBuffer = ReallocZ(packetBuffer, maximumPacketSize);
    }

    bytesRead = read(fd, packetBuffer, pktHeader.caplen);
    if (bytesRead != pktHeader.caplen)
    {
        fflush(stdout);
        fprintf(stdout, "Skipping  truncated packet: only %u bytes read\n", bytesRead);
        return;
    }

    struct eth_hdr* eth = (struct eth_hdr*) packetBuffer;
    if (debug == 1)
    {
        fprintf(stdout, "Ethernet header found, type: 0x%04x\n", ntohs(eth->type));
    }

    if (ntohs(eth->type) == ETHERTYPE_ARP)
    {
        fprintf(stdout, "Ethernet protocol: ARP\n");
    }
    else if (ntohs(eth->type) == ETHERTYPE_IP)
    {
        fprintf(stdout, "Ethernet protocol: IP\n");

        struct ipv4_header* iph = (struct ipv4_header*) (packetBuffer + sizeof(struct eth_hdr));
    
        if (verifyChecksum(iph, debug) == 0)
        {
            if (debug == 1)
            {
                fflush(stdout);
                fprintf(stderr, "Header checksum invalid, rejecting packet\n");
            }
            return;
        }

        addArpEntry(iph->sourceIP, eth->sourceMACAddress);

        if (debug == 1)
        {
            printIPv4Header(iph);
        } 
        
        char destination[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->destinationIP, destination, INET_ADDRSTRLEN);

        if (strcmp(destination, interface) == 0 || iph->destinationIP == broadcastAddress)
        {
            if (debug == 1)
            {
                fprintf(stdout, "Packet found for me\n");
            }

            size_t payloadLength;

            switch (iph->protocol)
            {
                case IPPROTO_ICMP:
                    fprintf(stdout, "IP protocol: ICMP\n");
                    struct icmp_header* icmpHeader = (struct icmp_header*)(packetBuffer + sizeof(struct eth_hdr) + ((iph->versionAndHeaderLength & 0X0F) * 4));
                    uint16_t headerLength = (iph->versionAndHeaderLength & 0X0F) * 4;
                    payloadLength = ntohs(iph->totalLength) - headerLength - sizeof(struct icmp_header);
                    uint8_t* icmp_payload = (uint8_t*)(icmpHeader + 1); // Payload starts after the ICMP header

                    if (verifyICMPChecksum(icmpHeader, icmp_payload, payloadLength, debug))
                    {
                        if (debug == 1)
                        {
                            fprintf(stdout, "ICMP checksum verified, packet accepted\n");
                        }
                        createPacket(fd, &pktHeader, eth, iph, icmpHeader, icmp_payload, &payloadLength, debug);
                    }
                    else
                    {
                        if (debug == 1)
                        {
                            fprintf(stdout, "ICMP checksum rejected, packet rejected\n");
                        }
                    } 
                    break;
                case IPPROTO_UDP:
                    fprintf(stdout, "IP protocol: UDP\n");
                    struct udp_header* udpHeader = (struct udp_header*)(packetBuffer + sizeof(struct eth_hdr) + ((iph->versionAndHeaderLength & 0X0F) * 4));
                    uint8_t* udpPayload = (uint8_t*)(udpHeader + 1);

                    if (verifyUDPChecksum(udpHeader, iph, udpPayload, &payloadLength, debug))
                    {
                        if (debug == 1)
                        {
                            fprintf(stdout, "UDP checksum verified, packet accepted\n");
                        }
                        createPacket(fd, &pktHeader, eth, iph, udpHeader, udpPayload, &payloadLength, debug);
                    }
                    else
                    {
                        if (debug == 1)
                        {
                            fprintf(stdout, "UDP checksum rejected, packet rejected\n");
                        }
                    }
                    break;
                case IPPROTO_TCP:
                    fprintf(stdout, "IP protocol: TCP\n");
                    struct tcp_header* tcpHeader = (struct tcp_header*)(packetBuffer + sizeof(struct eth_hdr) + ((iph->versionAndHeaderLength & 0X0F) * 4));
                    uint8_t* tcpPayload = (uint8_t*)(tcpHeader + 1);

                    if (verifyTCPChecksum(tcpHeader, iph, tcpPayload, &payloadLength, debug))
                    {
                        if (debug == 1)
                        {
                            fprintf(stdout, "TCP checksum verified, packet accepted\n");
                        }
                    }
                    else
                    {
                        if (debug == 1)
                        {
                            fprintf(stdout, "TCP checksum rejected, packet rejected\n");
                        }
                    }
                    break;
                default:
                    fprintf(stdout, "IP protocol: Unknown (%d)\n", iph->protocol);
                    break;
            }
        }
    }
}

void createPacket(const int fd, struct pcap_pkthdr* receivedPcapHeader, struct eth_hdr* receivedEthernetHeader, struct ipv4_header* receivedIPHeader, void* receivedProtocolHeader, uint8_t* receivedPayload, size_t* receivedPayloadLength, const int debug)
{
    uint32_t remainingCaptureLength = receivedPcapHeader->caplen;

    struct eth_hdr responseEthernetHeader;

    responseEthernetHeader = createResponseEthernetHeader(receivedEthernetHeader);
    remainingCaptureLength -= sizeof(struct eth_hdr);

    if (remainingCaptureLength > 0) // ipv4 header valid
    {
        switch (receivedIPHeader->protocol)
        {
            case IPPROTO_ICMP:
                if (debug == 1)
                {
                    fprintf(stdout, "Creating response for ICMP packet\n");
                }

                struct icmp_header responseICMPProtocolHeader = createResponseICMPHeader((struct icmp_header*) receivedProtocolHeader, receivedPayload, receivedPayloadLength, debug);
                struct ipv4_header responseIPv4Header = createResponseIPv4Header(receivedIPHeader, receivedPayloadLength, debug);

                struct pcap_pkthdr responsePcapHeader = createResponsePcapHeader(sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *receivedPayloadLength);
                sendPacket(fd, &responsePcapHeader, &responseEthernetHeader, &responseIPv4Header, &responseICMPProtocolHeader, receivedPayload, receivedPayloadLength);
                break;
            
            case IPPROTO_UDP:
                if (debug == 1)
                {
                    fprintf(stdout, "Creating response for UDP packet\n");
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
                        maximumPayloadSize = *receivedPayloadLength;
                        payload = MallocZ(*receivedPayloadLength);
                    }
                    else if (maximumPayloadSize < *receivedPayloadLength)
                    {
                        maximumPayloadSize = *receivedPayloadLength;
                        payload = ReallocZ(payload, *receivedPayloadLength);
                    }
                    payload = memcpy(payload, &total, *receivedPayloadLength);

                    *receivedPayloadLength = htons(*receivedPayloadLength);

                    responseUDPIPv4Header.totalLength = sizeof(struct ipv4_header) + sizeof(struct udp_header) + *receivedPayloadLength;
                    responseUDPIPv4Header.totalLength = (htons(responseUDPIPv4Header.totalLength));

                    responseUDPProtocolHeader = createResponseUDPHeader((struct udp_header*) receivedProtocolHeader, payload, receivedPayloadLength, &responseUDPIPv4Header, debug);

                    struct pcap_pkthdr responseUDPProtocolPcapHeader = createResponsePcapHeader(sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *receivedPayloadLength);
                    sendPacket(fd, &responseUDPProtocolPcapHeader, &responseEthernetHeader, &responseUDPIPv4Header, &responseUDPProtocolHeader, payload, receivedPayloadLength);
                    free(payload);
                }
                else // udp ping
                {
                    responseUDPIPv4Header.totalLength = sizeof(struct ipv4_header) + sizeof(struct udp_header) + *receivedPayloadLength;
                    
                    responseUDPProtocolHeader = createResponseUDPHeader((struct udp_header*) receivedProtocolHeader, receivedPayload, receivedPayloadLength, &responseUDPIPv4Header, debug);
                    
                    struct pcap_pkthdr responseUDPProtocolPcapHeader = createResponsePcapHeader(sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *receivedPayloadLength);

                    sendPacket(fd, &responseUDPProtocolPcapHeader, &responseEthernetHeader, &responseUDPIPv4Header, &responseUDPProtocolHeader, receivedPayload, receivedPayloadLength);
                }
                break;
            
            /*case IPPROTO_TCP:
                if (debug == 1)
                {
                    fprintf(stdout, "Creating response for TCP packet\n");
                }
                struct tcp_header responseTCPProtocolHeader = createResponseTCPHeader((struct tcp_header*) receivedProtocolHeader);
                uint8_t* responseTCPPayload = createResponsePayload(receivedPayload);
                break;*/
            
            default:
                fflush(stdout);
                fprintf(stderr, "Create Packet: Unsupported Protocol\n");
                break;
        }
    }

    else // Ethernet only packet (ARP)
    {

    }
}

struct eth_hdr createResponseEthernetHeader(struct eth_hdr* receivedEthernetHeader)
{
    struct eth_hdr responseHeader;
    memcpy(&responseHeader.destinationMACAddress, receivedEthernetHeader->sourceMACAddress, sizeof(responseHeader.destinationMACAddress));
    memcpy(&responseHeader.sourceMACAddress, receivedEthernetHeader->destinationMACAddress, sizeof(responseHeader.sourceMACAddress));
    responseHeader.type = receivedEthernetHeader->type;

    return responseHeader;
}

struct ipv4_header createResponseIPv4Header(struct ipv4_header* receivedIPHeader, size_t* payloadLength, const int debug)
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

            case IPPROTO_TCP:
                responseIPv4Header.totalLength += sizeof(struct tcp_header);
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
    responseIPv4Header.headerChecksum = calculateChecksum(&responseIPv4Header, debug);

    return responseIPv4Header;
}

struct icmp_header createResponseICMPHeader(struct icmp_header* receivedICMPHeader, uint8_t* payload, size_t* payloadLength, const int debug)
{
    struct icmp_header responseICMPHeader;
    responseICMPHeader.type = 0;
    responseICMPHeader.code = 0;
    responseICMPHeader.checkSum = 0;
    responseICMPHeader.identifier = receivedICMPHeader->identifier;
    responseICMPHeader.sequenceNumber = receivedICMPHeader->sequenceNumber;

    responseICMPHeader.checkSum = calculateICMPChecksum(&responseICMPHeader, payload, payloadLength, debug);

    return responseICMPHeader;
}

struct udp_header createResponseUDPHeader(struct udp_header* receivedUDPHeader, uint8_t* payload, size_t* payloadLength, struct ipv4_header* responseIPv4Header, const int debug)
{
    // Received header is passed in for modification to be used for response
    responseIPv4Header->timeToLive = 64;
    uint32_t temp = responseIPv4Header->sourceIP;
    responseIPv4Header->sourceIP = responseIPv4Header->destinationIP;
    responseIPv4Header->destinationIP = temp;
    responseIPv4Header->headerChecksum = 0;
    responseIPv4Header->headerChecksum = calculateChecksum(responseIPv4Header, debug);

    struct udp_header responseUDPHeader;
    responseUDPHeader.sourcePort = receivedUDPHeader->destinationPort;
    responseUDPHeader.destinationPort = receivedUDPHeader->sourcePort;
    responseUDPHeader.length = sizeof(struct udp_header) + *payloadLength;
    responseUDPHeader.checksum = 0;
    responseUDPHeader.checksum = calculateUDPChecksum(&responseUDPHeader, responseIPv4Header, payload, payloadLength, debug);
    
    return responseUDPHeader;
}

/*struct tcp_header createResponseTCPHeader(struct tcp_header* receivedTCPHeader)
{
    struct tcp_header responseTCPHeader;
    return responseTCPHeader;
}*/

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

void sendPacket(const int fd, struct pcap_pkthdr* pcapHeader, struct eth_hdr* ethernetHeader, struct ipv4_header* ipHeader, void* protocolHeader, uint8_t* payload, size_t* payloadLength)
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

    fprintf(stdout, "total length %u\n", ipHeader->totalLength);
    fprintf(stdout, "size: %lu\n", sizeof(struct eth_hdr) + sizeof(struct ipv4_header) + sizeof(struct icmp_header) + *payloadLength);
    fprintf(stdout, "payload size: %lu\n", *payloadLength);

    while (success == -1)
    {
        success = writev(fd, iov, 5);
    }
    fprintf(stdout, "SIZE ACTUALLY WRITTEN: %d\n", success);
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

void freePacketBufferAndPayload()
{
    if (packetBuffer != NULL)
    {
        free(packetBuffer);
        packetBuffer = NULL;
    }
    if (payload != NULL)
    {
        free(payload);
        payload = NULL;
    }
}