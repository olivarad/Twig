#pragma once 
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

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
	uint16_t flagsAndFragmentOffset; // 1 bit reserved, 1 bit don't fragment, 1 bit more frgament, 13 bit fragment offset
	uint8_t timeToLive;
	uint8_t protocol;
	uint16_t headerChecksum;
	uint32_t sourceIP;
	uint32_t destinationIP;
};

struct arp_header
{
	uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

struct tcp_header
{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint32_t sequence;
	uint32_t ack;
	uint8_t dataOffset;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgentPointer;
};

struct tcp_pseudo_header
{
    uint32_t source_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

struct udp_header
{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t length;
	uint16_t checksum;
};

struct udp_pseudo_header
{
    uint32_t source_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t udp_length;
};

struct icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checkSum;
    uint16_t identifier;
    uint16_t sequenceNumber;
};

void printUsage(const char* program);

void printHelp();

void checkInterface(const char* interface);

char* calculateNetworkAddress(const char *address, char* networkAddress, int debug);

void trimInterface(char* interface, int debug);

int readFileHeader(const int fd);

void readPacket(const int fd, char* interface, int debug);

void createPacket(const int fd, struct pcap_pkthdr* receivedPcapHeader, struct eth_hdr* receivedEthernetHeader, struct ipv4_header* receivedIPHeader, void* receivedProtocolHeader, uint8_t* receivedPayload, size_t* receivedPayloadLength);

struct eth_hdr createResponseEthernetHeader(struct eth_hdr* receivedEthernetHeader);

struct ipv4_header createResponseIPv4Header(struct ipv4_header* receivedIPHeader, size_t* payloadLength);

struct icmp_header createResponseICMPHeader(struct icmp_header* receivedICMPHeader, uint8_t* payload, size_t* payloadLength);

struct udp_header createResponseUDPHeader(struct udp_header* receivedUDPHeader, uint8_t* payload, size_t* payloadLength, struct ipv4_header* responseIPv4Header);

struct tcp_header createResponseTCPHeader(struct tcp_header* receivedTCPHeader);

uint8_t* createResponsePayload(uint8_t* receivedPayload);

struct pcap_pkthdr createResponsePcapHeader(unsigned CapLen);

void sendPacket(const int fd, struct pcap_pkthdr* pcapHeader, struct eth_hdr* ethernetHeader, struct ipv4_header* ipHeader, void* protocolHeader, uint8_t* payload, size_t* payloadLength);

void* MallocZ (int nbytes);