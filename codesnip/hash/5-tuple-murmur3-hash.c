/*
from chatgpt

Here’s a MurmurHash3 (32-bit) hash function implementation in C for a 5-tuple:

5-Tuple Inputs
	src_ip: IPv4 source address (uint32_t)
	dst_ip: IPv4 destination address (uint32_t)
	src_port: TCP/UDP source port (uint16_t)
	dst_port: TCP/UDP destination port (uint16_t)
	protocol: IP protocol (uint8_t)

Key Features of MurmurHash3
	1.	Good Mixing:
		  MurmurHash3 ensures excellent bit dispersion, meaning small changes in the input produce large changes in the output.
	2.	Deterministic:
		  The hash function produces the same output for the same inputs, which is critical for hash table lookups and other applications.
	3.	Fast:
		  The function uses simple arithmetic and bitwise operations, making it highly efficient for real-time or high-throughput applications.
	4.	Seed Support:
		  The seed parameter allows for generating different hash values for the same input data, which is useful in certain applications like hash tables with multiple hash functions.


Use Cases for 5-Tuple Hashing
	1.	Networking:
		  Load balancing, flow hashing, and packet processing use the 5-tuple (source IP, destination IP, source port, destination port, protocol) to uniquely identify network flows.
	2.	Hash Tables:
		  Efficiently hash the 5-tuple for storing and retrieving flow-related metadata.
	3.	Distributed Systems:
		  Use the hash to distribute traffic evenly across servers or nodes.
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>

uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed) {
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    uint32_t h1 = seed;
    size_t nblocks = len / 4;

    const uint32_t* blocks = (const uint32_t*)(key);
    for (size_t i = 0; i < nblocks; i++) {
        uint32_t k1 = blocks[i];

        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    const uint8_t* tail = (const uint8_t*)(key + nblocks * 4);
    uint32_t k1 = 0;

    switch (len & 3) {
        case 3: k1 ^= tail[2] << 16;
        case 2: k1 ^= tail[1] << 8;
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = rotl32(k1, 15);
                k1 *= c2;
                h1 ^= k1;
    }

    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

uint32_t murmurhash3_5tuple(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t protocol, uint32_t seed) {
    uint8_t data[13];
    memcpy(&data[0],  &src_ip, 4);
    memcpy(&data[4],  &dst_ip, 4);
    memcpy(&data[8],  &src_port, 2);
    memcpy(&data[10], &dst_port, 2);
    data[12] = protocol;

    return murmur3_32(data, sizeof(data), seed);
}

int main() {
    uint32_t src_ip = 0xC0A80101;     // 192.168.1.1
    uint32_t dst_ip = 0x08080808;     // 8.8.8.8
    uint16_t src_port = 12345;
    uint16_t dst_port = 80;
    uint8_t protocol = 6;             // TCP
    uint32_t seed = 0x12345678;

    uint32_t hash = murmurhash3_5tuple(src_ip, dst_ip, src_port, dst_port, protocol, seed);
    printf("MurmurHash3 (5-tuple) = 0x%08X\n", hash);

    return 0;
}

