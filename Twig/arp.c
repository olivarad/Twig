#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "arp.h"

#define MAX_ARP_ENTRIES 100

struct arphdr 
{
    uint16_t htype;    // Hardware type (Ethernet = 1)
    uint16_t ptype;    // Protocol type (IPv4 = 0x0800)
    uint8_t hlen;      // Hardware address length
    uint8_t plen;      // Protocol address length
    uint16_t operation; // ARP operation (request = 1, reply = 2)
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

typedef struct 
{
    uint32_t ip;
    uint8_t mac[6];
} ArpEntry;

ArpEntry arpTable[MAX_ARP_ENTRIES];
unsigned arpCount = 0;

void addArpEntry(uint32_t ip, uint8_t mac[6]) 
{
    ip = ntohl(ip); // host byte order

    for (unsigned i = 0; i < arpCount; ++i)
    {
        if (arpTable[i].mac == mac)
        {
            if (arpTable[i].ip != ip) // ip has been changed for this interface
            {
                arpTable[i].ip = ip;
            }
            return;
        }
    }
    // Entry not found in table
    if (arpCount < MAX_ARP_ENTRIES) 
    {
        arpTable[arpCount].ip = ip;
        memcpy(arpTable[arpCount].mac, mac, 6);
        ++arpCount;
    }
    else
    {
        fprintf(stdout, "HEY SILLY GOOBER, DON'T FORGET TO DELETE OLD ARP ENTRIES\n");
    }
}

int lookupArpEntry(uint32_t ip, uint8_t* result[6]) 
{
    for (unsigned i = 0; i < arpCount; ++i) 
    {
        if (arpTable[i].ip == ip) 
        {
            memcpy(result, arpTable[i].mac, 6);
            return 1;
        }
    }
    return 0;
}