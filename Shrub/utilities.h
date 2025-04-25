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

// ALWAYS HOST BYTE ORDER
struct pcap_pkthdr 
{
	bpf_u_int32 ts_secs;		/* time stamp */
	bpf_u_int32 ts_usecs;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};

// ALWAYS HOST BYTE ORDER
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
	uint32_t sourceIP; // DUE TO SILLYNESS I OFTEN STORE THESE IN HOST ORDER BUT THEY SHOULD BE IN NETWORK ORDER WHEN DOING BASICALLY ANYTHING WITH THEM, ESPECIALLY SENDING
	uint32_t destinationIP; // SAME
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

struct rip_header
{
	uint8_t command;
	uint8_t version;
	uint16_t zero;
};

// Convert to network byte order before sending
struct rip_entry
{
	uint16_t addressFamilyIdentifier;
	uint16_t routeTag;
	uint32_t address; // Where you advertise a route to
	uint32_t subnetMask;
	uint32_t nextHop;
	uint32_t metric; // hop count (0 - 16, 16 = unreachable)
};

struct rip_table_entry
{
	struct rip_entry entry;
	u_int8_t advertiserMACAddress[6]; // who gave you the info+
};

struct readPacketArguments
{
	int count;
	int fd;
	int** fileDescriptors;
	char* interface;
	char** interfaces;
	uint32_t broadcastAddress;
	uint8_t mac[6];
	int debug;
	size_t* maximumPacketSize;
	size_t* maximumPayloadSize;
	char* packetBuffer;
	uint8_t* payload;
};

void printUsage(const char* program);

void printHelp();

void checkInterface(char* interface);

char** calculateNetworkBroadcastAndSubnetLength(char** addresses, char** networkAddresses, uint32_t* broadcastAddresses, uint8_t* subnetLengths, const unsigned count, const int debug);

void trimInterfaces(char** interfaces, const unsigned count, int debug);

void printRouteTable(struct rip_table_entry** routeTable, const unsigned count);

void createDefaultRouteTable(struct rip_table_entry** routeTable, char** networkAddresses, char** interfaces, uint8_t* subnetLengths, const unsigned interfaceCount, const unsigned routeCount, const int debug);

time_t advertiseRIP(struct rip_table_entry** routeTable, int** fileDescriptors, char** interfaces, char** networkAddresses, const unsigned interfaceCount, const unsigned maxRoutes, const int debug);

void sendRIP(struct rip_entry entries[25], unsigned ripEntryCount, int fd, char* interface, const int debug);

void receiveRIP(uint8_t* payload, size_t payloadSize);

int embedIPv4InMac(const char* IPv4, uint8_t mac[6]);

int readFileHeader(const int fd);

void* readPacket(void* args);

void createPacket(const int fd, struct pcap_pkthdr* receivedPcapHeader, struct eth_hdr* receivedEthernetHeader, struct ipv4_header* receivedIPHeader, void* receivedProtocolHeader, uint8_t* receivedPayload, size_t* receivedPayloadLength, uint8_t* payload, size_t* maximumPayloadSize, uint8_t* mac, char* interface, const int debug);

struct eth_hdr createResponseEthernetHeader(struct eth_hdr* receivedEthernetHeader, uint8_t* mac);

struct ipv4_header createResponseIPv4Header(struct ipv4_header* receivedIPHeader, size_t* payloadLength, char* interface, const int debug);

struct icmp_header createResponseICMPHeader(struct icmp_header* receivedICMPHeader, uint8_t* payload, size_t* payloadLength, char* interface, const int debug);

struct udp_header createResponseUDPHeader(struct udp_header* receivedUDPHeader, uint8_t* payload, size_t* payloadLength, struct ipv4_header* responseIPv4Header, char* interface, const int debug);

uint8_t* createResponsePayload(uint8_t* receivedPayload);

struct pcap_pkthdr createResponsePcapHeader(unsigned CapLen);

// Protocol Header length in host byte order
void sendPacket(const int fd, struct pcap_pkthdr* pcapHeader, struct eth_hdr* ethernetHeader, struct ipv4_header* ipHeader, void* protocolHeader, size_t protocolHeaderLength, uint8_t* payload, size_t* payloadLength, char* interface, const int debug);

void* MallocZ (int nbytes);

void* ReallocZ(void* ptr, size_t nbytes);