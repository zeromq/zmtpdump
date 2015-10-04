#include "analyzetcp.h"
#include <assert.h>

int PacketIsEthernet(const uint8_t *packet, size_t len)
{
    return 1;
}

int PacketEthernetPayloadIsIP(const uint8_t *packet, size_t len)
{
    uint8_t payload_type[2] = { 0x08, 0x00 };
    if (len < 14)
        return 0;
    return (memcmp(payload_type, packet + 12, 2) == 0);
}

int PacketExtractIP(const uint8_t *packet, size_t len,
  const uint8_t **ip_start, size_t *ip_len)
{
    assert(ip_start);
    assert(ip_len);
    if (!PacketIsEthernet(packet, len))
        return 0;
    *ip_start = packet + 14;
    *ip_len = ((*ip_start)[0] & 0x0f) * 4;
    return 1;
}

int PacketIsIP(uint8_t *packet, size_t len)
{
    assert(packet);
    if (len < 20)
        return 0;
    return (packet[0] == 0x45);
}

int PacketIPPayloadIsTCP(uint8_t *packet, size_t len)
{
    assert(packet);
    assert(PacketIsIP(packet, len));
    return (packet[9] == 0x06);
}

int PacketExtractTCP(const uint8_t *packet, size_t len,
  const uint8_t **tcp_start, size_t *tcp_len)
{
    assert(packet);
    assert(tcp_start);
    assert(tcp_len);
    const uint8_t *ip_start;
    size_t ip_len;
    int res = PacketExtractIP(packet, len, &ip_start, &ip_len);
    if (!res)
        return 0;
    *tcp_start = ip_start + ip_len;
    *tcp_len = (((*tcp_start)[12] & 0xf0) >> 4) * 4;
    return 1;
}

int PacketIPGetAddress(const uint8_t *packet, size_t len, const uint8_t **src_address,
    const uint8_t **dst_address)
{
    assert(packet);
    assert(src_address);
    assert(dst_address);
    const uint8_t *ip_start;
    size_t ip_len;
    int res = PacketExtractIP(packet, len, &ip_start, &ip_len);
    if (!res)
        return 0;
    *src_address = ip_start + 12;
    *dst_address = ip_start + 16;
    return 1;
}

int PacketTCPGetPort(const uint8_t *packet, size_t len,
    const uint8_t **src_port,
    const uint8_t **dst_port)
{
    assert(packet);
    assert(src_port);
    assert(dst_port);
    int res;
    const uint8_t *tcp_start;
    size_t tcp_len;
    res = PacketExtractTCP(packet, len, &tcp_start, &tcp_len);
    if (!res)
        return 0;
    *src_port = tcp_start;
    *dst_port = tcp_start + 2;
    return 1;
}

int PacketTCPGetFlags(const uint8_t *packet, size_t len)
{
    assert(packet);
    assert(len > 0);
    return ((packet[12] & 0x01) << 8) | packet[13];
}

int PacketTCPGetFlagSYN(const uint8_t *packet, size_t len)
{
    int flags = PacketTCPGetFlags(packet, len);
    return (flags & 0x02) >> 1;
}

int PacketTCPGetFlagACK(const uint8_t *packet, size_t len)
{
    int flags = PacketTCPGetFlags(packet, len);
    return (flags & 0x10) >> 4;
}

int PacketTCPGetFlagFIN(const uint8_t *packet, size_t len)
{
    int flags = PacketTCPGetFlags(packet, len);
    return (flags & 0x01);
}

int PacketTCPGetFlagRST(const uint8_t *packet, size_t len)
{
    int flags = PacketTCPGetFlags(packet, len);
    return (flags & 0x04) >> 2;
}

int PacketTCPGetFlagPSH(const uint8_t *packet, size_t len)
{
    int flags = PacketTCPGetFlags(packet, len);
    return (flags & 0x08) >> 3;
}

int PacketExtractData(const uint8_t *packet, size_t len,
  const uint8_t **data_start, size_t *data_len)
{
    assert(packet);
    assert(data_start);
    assert(data_len);
    int res;
    const uint8_t *tcp_start;
    size_t tcp_len;
    res = PacketExtractTCP(packet, len, &tcp_start, &tcp_len);
    if (!res)
        return 0;
    *data_start = tcp_start + tcp_len;
    *data_len = packet + len - *data_start;
    return 1;
}
