#include "CuTest.h"
#include <stdint.h>

void TestExtractTcp(CuTest *tc)
{
//    CuFail(tc, "testing the test");
    // packet contains a whole packet captured by libpcap:
    // ethernet header + IP header + TCP header + TCP payload
    uint8_t packet[] =
    {
        // Ethernet header, 14 bytes
        //     destination: 00 00 00 00 00 00 (MAC address 0, localhost)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        //     source: 00 00 00 00 00 00 (MAC address 0, localhost)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        //     type: IP 08 00
        0x08, 0x00,

        // IP header, 20 bytes
        //     Version+header length: 45 (version 4, header length 20), 1 byte
        0x45,
        //     Differentiated Services Field: 0, 1 byte
        0x00,
        //     Total length: 0x00 0x3c (60), 2 bytes
        0x00, 0x3c,
        //     Identification: 0x31 0x2e, 2 bytes
        0x31, 0x2e,
        //     Flags + Fragment offset: 40 (flags 02 (Don't Fragment), Offset 0), 2 bytes
        0x40, 0x00,
        //     Time to live: 0x40 (64), 1 byte
        0x40,
        //     Protocol: 0x06 (TCP), 1 byte
        0x06,
        //     Header checksum: 0x0b 0x8c, 2 bytes
        0x0b, 0x8c,
        //     Source: 0x7f 00 00 01 (127.0.0.1, localhost), 4 bytes
        0x7f, 0x00, 0x00, 0x01,
        //     Destination: 0x7f 00 00 01 (127.0.0.1, localhost), 4 bytes
        0x7f, 0x00, 0x00, 0x01,

        // TCP header, 40 bytes
        //     Source port: 0xa5 0xc8 (42440), 2 bytes
        0xa5, 0xc8,
        //     Destination port: 0x1b 0x59 (7001), 2 bytes
        0x1b, 0x59,
        //     Sequence number: 0x15 0xc5 0xed 0xeb, 4 bytes
        0x15, 0xc5, 0xed, 0xeb,
        //     Acknowledgement number: 00 00 00 00, 4 bytes (0 because ACK flag is 0)
        0x00, 0x00, 0x00, 0x00,
        //     Header length (Data offset): 0xa (10 * 4 bytes), 4 bits
        //     Reserved: 0b000, 3 bits
        //     Flags: 0x02 (SYN), 9 bits
        0xa0, 0x02,
        //     Window size: 0x80 0x18 (32792), 2 bytes
        0x80, 0x18,
        // Checksum: 0xed 0x1b
        0xed, 0x1b,
        // Options: 20 bytes
        0x00, 0x00, 0x02, 0x04,
        0x40, 0x0c, 0x04, 0x02, 0x08, 0x0a, 0x00, 0xd9,
        0xdc, 0xc5, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x07
    };
    
    int res;
    
    res = PacketIsEthernet(packet, sizeof(packet));
    CuAssertIntEquals(tc, 1, res);
    
    res = PacketEthernetPayloadIsIP(packet, sizeof(packet));
    CuAssertIntEquals(tc, 1, res);
    
    uint8_t *ip_start;
    size_t ip_len;
    res = PacketExtractIP(packet, sizeof(packet), &ip_start, &ip_len);
    CuAssertIntEquals(tc, 1, res);
    CuAssertPtrEquals(tc, packet + 14, ip_start);
    CuAssertIntEquals(tc, 20, ip_len);

    res = PacketIsIP(ip_start, ip_len);
    CuAssertIntEquals(tc, 1, res);

    // Extracting source and destination IP addresses from the IP header.
    uint8_t *src_address;
    uint8_t *dst_address;
    uint8_t src_address_check[] = { 0x7f, 0x00, 0x00, 0x01 };
    uint8_t dst_address_check[] = { 0x7f, 0x00, 0x00, 0x01 };
    res = PacketIPGetAddress(packet, sizeof(packet), &src_address,
        &dst_address);
    CuAssertTrue(tc, res);
    CuAssertTrue(tc, memcmp(src_address, src_address_check, 4) == 0);
    CuAssertTrue(tc, memcmp(dst_address, dst_address_check, 4) == 0);

    // Extracting source and destination ports from the TCP header.
    uint8_t *src_port;
    uint8_t *dst_port;
    uint8_t src_port_check[] = { 0xa5, 0xc8 };
    uint8_t dst_port_check[] = { 0x1b, 0x59 };
    res = PacketTCPGetPort(packet, sizeof(packet), &src_port,
        &dst_port);
    CuAssertTrue(tc, res);
    CuAssertTrue(tc, memcmp(src_port, src_port_check, 2) == 0);

    res = PacketIPPayloadIsTCP(ip_start, ip_len);
    CuAssertIntEquals(tc, 1, res);
    
    uint8_t *tcp_start;
    size_t tcp_len;
    res = PacketExtractTCP(packet, sizeof(packet), &tcp_start, &tcp_len);
    CuAssertIntEquals(tc, 1, res);
    CuAssertPtrEquals(tc, packet + 34, tcp_start);
    CuAssertIntEquals(tc, 40, tcp_len);

    res = PacketTCPGetFlags(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0x02, res);
    
    res = PacketTCPGetFlagSYN(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 1, res);
    
    res = PacketTCPGetFlagACK(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0, res);
    
    res = PacketTCPGetFlagFIN(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0, res);
    
    res = PacketTCPGetFlagRST(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0, res);
    
    res = PacketTCPGetFlagPSH(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0, res);
}

void TestExtractTcpPayload(CuTest *tc)
{
    // packet that includes payload
    // See data-details.xml (exported from Wireshark)
    // Frame Number: 5066
    uint8_t packet[] =
    {
        // Ethernet, 14 bytes
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        // IP, 20 bytes
0x45, 0x00,
0x00, 0x3e, 0x2e, 0xfb, 0x40, 0x00, 0x40, 0x06,
0x0d, 0xbd, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
0x00, 0x01,
        // TCP, 32 bytes
0xc4, 0xb3, 0x1b, 0x59, 0x12, 0x8b,
0x8c, 0x87, 0x12, 0x50, 0x3e, 0x70, 0x80, 0x18,
0x01, 0x01, 0xfe, 0x32, 0x00, 0x00, 0x01, 0x01,
0x08, 0x0a, 0x02, 0x87, 0xa2, 0x7f, 0x02, 0x87,
0xa2, 0x7f,
        // data, 10 bytes
0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x01, 0x7f
    };

    int res;

    // Analyze Ethernet header.

    res = PacketIsEthernet(packet, sizeof(packet));
    CuAssertIntEquals(tc, 1, res);

    res = PacketEthernetPayloadIsIP(packet, sizeof(packet));
    CuAssertIntEquals(tc, 1, res);

    uint8_t *ip_start;
    size_t ip_len;
    res = PacketExtractIP(packet, sizeof(packet), &ip_start, &ip_len);
    CuAssertIntEquals(tc, 1, res);
    CuAssertPtrEquals(tc, packet + 14, ip_start);
    CuAssertIntEquals(tc, 20, ip_len);

    res = PacketIsIP(ip_start, ip_len);
    CuAssertIntEquals(tc, 1, res);

    // Analyze IP layer.

    res = PacketIPPayloadIsTCP(ip_start, ip_len);
    CuAssertIntEquals(tc, 1, res);

    uint8_t *tcp_start;
    size_t tcp_len;
    res = PacketExtractTCP(packet, sizeof(packet), &tcp_start, &tcp_len);
    CuAssertIntEquals(tc, 1, res);
    CuAssertPtrEquals(tc, packet + 34, tcp_start);
    CuAssertIntEquals(tc, 32, tcp_len);

    // Analyze TCP layer.

    res = PacketTCPGetFlags(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0x18, res); // 0x18 (PSH, ACK)

    res = PacketTCPGetFlagSYN(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0, res);

    res = PacketTCPGetFlagACK(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 1, res);

    res = PacketTCPGetFlagFIN(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0, res);

    res = PacketTCPGetFlagRST(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 0, res);

    res = PacketTCPGetFlagPSH(tcp_start, tcp_len);
    CuAssertIntEquals(tc, 1, res);

    // Get data.

    uint8_t *data_start;
    size_t data_len;
    res = PacketExtractData(packet, sizeof(packet),
      &data_start, &data_len);
    CuAssertTrue(tc, res);
    CuAssertPtrEquals(tc, packet + 66, data_start);
    CuAssertIntEquals(tc, 10, data_len);
}

CuSuite* CuGetSuite_tcp(void)
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, TestExtractTcp);
    SUITE_ADD_TEST(suite, TestExtractTcpPayload);

    return suite;
}
