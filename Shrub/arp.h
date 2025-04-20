#pragma once

void addArpEntry(uint32_t ip, uint8_t mac[6]);

int lookupArpEntry(uint32_t ip, uint8_t* result[6]);