/*
from chatgpt

Below is a full C example that implements Bob Jenkins’ lookup3 hash for a 5‑tuple. 
In this example the five inputs are:

    src_ip (32‑bit)
    dst_ip (32‑bit)
    src_port (16‑bit)
    dst_port (16‑bit)
    protocol (8‑bit)

The code packs these into a 13‑byte key (using little‑endian ordering), then processes 
one complete 12‑byte block and a 1‑byte tail. It uses the standard macros for mixing 
(mix()) and finalization (final()) as defined in Bob Jenkins’ lookup3 function.

Explanation
Packing the Key:
We pack the five-tuple into a 13‑byte array (4 bytes for each IP, 2 bytes each 
for the ports, and 1 byte for protocol). We use little‑endian order for consistency 
with typical lookup3 usage.

Initialization:
The internal state variables a, b, and c are initialized to
0xdeadbeef + length + seed
where length is 13 bytes and seed is provided by the caller.

Processing the Main Block:
We process 12 bytes (the full block) by reading 32‑bit words from the key.

Handling the Tail:
With 13 bytes total, one byte remains. Per the lookup3 convention 
(here, adding any leftover byte to a), we add the remaining byte.

Final Mixing:
The final() macro is then called to avalanche the internal state.

Output:
The function returns the final 32‑bit hash value, which is printed in hexadecimal.
*/

#include <stdint.h>
#include <stdio.h>

// Define the 32-bit rotate macro
#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

// The mix() macro mixes 3 32-bit values reversibly.
#define mix(a,b,c)                        \
{                                           \
    a -= c;  a ^= rot(c, 4);  c += b;         \
    b -= a;  b ^= rot(a, 6);  a += c;         \
    c -= b;  c ^= rot(b, 8);  b += a;         \
    a -= c;  a ^= rot(c,16);  c += b;         \
    b -= a;  b ^= rot(a,19);  a += c;         \
    c -= b;  c ^= rot(b, 4);  b += a;         \
}

// The final() macro force all bits of a, b, and c to avalanche.
#define final(a,b,c)                      \
{                                           \
    c ^= b; c -= rot(b,14);                  \
    a ^= c; a -= rot(c,11);                  \
    b ^= a; b -= rot(a,25);                  \
    c ^= b; c -= rot(b,16);                  \
    a ^= c; a -= rot(c,4);                   \
    b ^= a; b -= rot(a,14);                  \
    c ^= b; c -= rot(b,24);                  \
}

// jenkins_hash_5tuple() computes a Jenkins lookup3 hash for a 5-tuple.
// The five fields are packed into a 13-byte key in little-endian order.
uint32_t jenkins_hash_5tuple(uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint8_t protocol,
                             uint32_t seed)
{
    // Pack the five-tuple into a 13-byte key.
    uint8_t key[13];
    // Pack source IP (32-bit)
    key[0] = (uint8_t)(src_ip & 0xFF);
    key[1] = (uint8_t)((src_ip >> 8) & 0xFF);
    key[2] = (uint8_t)((src_ip >> 16) & 0xFF);
    key[3] = (uint8_t)((src_ip >> 24) & 0xFF);
    // Pack destination IP (32-bit)
    key[4] = (uint8_t)(dst_ip & 0xFF);
    key[5] = (uint8_t)((dst_ip >> 8) & 0xFF);
    key[6] = (uint8_t)((dst_ip >> 16) & 0xFF);
    key[7] = (uint8_t)((dst_ip >> 24) & 0xFF);
    // Pack source port (16-bit)
    key[8] = (uint8_t)(src_port & 0xFF);
    key[9] = (uint8_t)((src_port >> 8) & 0xFF);
    // Pack destination port (16-bit)
    key[10] = (uint8_t)(dst_port & 0xFF);
    key[11] = (uint8_t)((dst_port >> 8) & 0xFF);
    // Pack protocol (8-bit)
    key[12] = protocol;

    // Total length is 13 bytes.
    uint32_t length = 13;

    // Initialize the internal state. (Typical initial value is 0xdeadbeef.)
    uint32_t a, b, c;
    a = b = c = 0xdeadbeef + length + seed;

    // Process the one full 12-byte block.
    a += key[0]  | (key[1]  << 8) | (key[2]  << 16) | (key[3]  << 24);
    b += key[4]  | (key[5]  << 8) | (key[6]  << 16) | (key[7]  << 24);
    c += key[8]  | (key[9]  << 8) | (key[10] << 16) | (key[11] << 24);

    // Since 13 mod 12 = 1, we have one extra byte.
    // Following lookup3's tail processing (for 1 leftover byte, add it to 'a')
    switch(length - 12) {
        case 1:
            a += key[12];
            break;
        // (Other cases do not occur for a fixed 13-byte key)
    }

    // Final mixing of the internal state.
    final(a, b, c);

    // Return the final 32-bit hash value.
    return c;
}

int main(void)
{
    // Example 5-tuple inputs.
    uint32_t src_ip = 0xC0A80101;  // 192.168.1.1
    uint32_t dst_ip = 0x08080808;  // 8.8.8.8
    uint16_t src_port = 12345;
    uint16_t dst_port = 80;
    uint8_t protocol = 6;          // TCP
    uint32_t seed = 0x12345678;    // Arbitrary seed value

    uint32_t hash = jenkins_hash_5tuple(src_ip, dst_ip, src_port, dst_port, protocol, seed);
    printf("Jenkins lookup3 hash: 0x%08X\n", hash);

    return 0;
}

