#ifndef _analyzetcp_h_INC_
#define _analyzetcp_h_INC_

#include <stdint.h>
#include <stdlib.h>

int PacketIsEthernet(const uint8_t *packet, size_t len);
int PacketEthernetPayloadIsIP(const uint8_t *packet, size_t len);
int PacketExtractIP(const uint8_t *packet, size_t len,
  const uint8_t **ip_start, size_t *ip_len);

int PacketIsIP(uint8_t *packet, size_t len);
int PacketIPPayloadIsTCP(uint8_t *packet, size_t len);

int PacketIPGetAddress(const uint8_t *packet, size_t len,
    const uint8_t **src_address,
    const uint8_t **dst_address);
int PacketExtractTCP(const uint8_t *packet, size_t len,
  const uint8_t **tcp_start, size_t *tcp_len);

int PacketTCPGetPort(const uint8_t *packet, size_t len,
    const uint8_t **src_port,
    const uint8_t **dst_port);

/** Get TCP flags (9 bits)
 *
 * Extract flags from TCP header. Flags are bit 0 of byte 12 (NS) and
 * all bits of byte 13 (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN).
 */
int PacketTCPGetFlags(const uint8_t *packet, size_t len);
int PacketTCPGetFlagSYN(const uint8_t *packet, size_t len);
int PacketTCPGetFlagACK(const uint8_t *packet, size_t len);
int PacketTCPGetFlagFIN(const uint8_t *packet, size_t len);
int PacketTCPGetFlagRST(const uint8_t *packet, size_t len);
int PacketTCPGetFlagPSH(const uint8_t *packet, size_t len);

int PacketExtractData(const uint8_t *packet, size_t len,
  const uint8_t **data_start, size_t *data_len);

#endif /* !_analyzetcp_h_INC_ */
