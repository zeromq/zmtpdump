#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include "analyzetcp.h"
#include "cset.h"
#include "analyzezmtp.h"
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

cset_t *cset;

int fl_verbose = 0;

void
showbytes(const u_char *data, size_t len)
{
    size_t i, j;

    for (i = 0, j = 0; i < len; i++) {
        u_char ch = data[i];
        if (isprint(ch))
            printf("%02x(%c) ", (int) ch, ch);
        else
            printf("%02x(\?) ", (int) ch);
        j++;
        if (j == 8) {
            j = 0;
            printf("\n");
        }
    }
    if (j > 0)
        printf("\n");
}

void zmtp_handler(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    int res = gettimeofday(&tv, NULL);
    if (res < 0)
        exit(-1);
    struct tm *tm = localtime(&tv.tv_sec);
    if (tm == NULL)
        exit(-1);

    const uint8_t *tcp_start;
    size_t tcp_len;

    size_t len = header->len;
    const uint8_t *data_start;
    size_t data_len;
    res = PacketExtractData(packet, len, &data_start, &data_len);

    res = PacketExtractTCP(packet, len, &tcp_start, &tcp_len);
    if (!res) {
        fprintf(stderr, "Failed to extract TCP\n");
        goto Error;
    }

    res = PacketIsEthernet(packet, len);
    if (!res) {
        fprintf(stderr, "Packet is not Ethernet\n");
        goto Error;
    }
    res = PacketEthernetPayloadIsIP(packet, len);
    if (!res) {
        fprintf(stderr, "Payload is not IP\n");
        goto Error;
    }

    const uint8_t *src_address;
    const uint8_t *dst_address;
    res = PacketIPGetAddress(packet, len, &src_address, &dst_address);
    if (!res)
        goto Error;

    const uint8_t *src_port;
    const uint8_t *dst_port;
    res = PacketTCPGetPort(packet, len, &src_port, &dst_port);
    if (!res)
        goto Error;

    if (PacketTCPGetFlagSYN(tcp_start, tcp_len))
        CSetRemove(cset, src_address, src_port, dst_address, dst_port);

    if (!fl_verbose && (data_len == 0))
        return;

    printf("----------------------------\n");
    printf("%02d:%02d:%02d.%03d\n",
        tm->tm_hour, tm->tm_min, tm->tm_sec, (int) (tv.tv_usec / 1000));
    printf("Packet size: %d bytes\n", (int) len);
    printf("Payload size: %d bytes\n", (int) data_len);

    char id[256];
    sprintf(id, "[%d.%d.%d.%d:%d, %d.%d.%d.%d:%d]",
        src_address[0], src_address[1], src_address[2], src_address[3],
        (src_port[0] << 8) + src_port[1],
        dst_address[0], dst_address[1], dst_address[2], dst_address[3],
        (dst_port[0] << 8) + dst_port[1]);

    if (fl_verbose) {
        printf("%s ", id);
        res = PacketTCPGetFlagSYN(tcp_start, tcp_len);
        if (res) printf("SYN ");
        res = PacketTCPGetFlagACK(tcp_start, tcp_len);
        if (res) printf("ACK ");
        res = PacketTCPGetFlagFIN(tcp_start, tcp_len);
        if (res) printf("FIN ");
        res = PacketTCPGetFlagRST(tcp_start, tcp_len);
        if (res) printf("RST ");
        res = PacketTCPGetFlagPSH(tcp_start, tcp_len);
        if (res) printf("PSH ");
        printf("\n");
    }

    void *value;
    zmtpreader_t *reader;
    value = CSetFind(cset, src_address, src_port, dst_address, dst_port);
    if (value == NULL) {
        reader = ZmtpReaderNew();
        assert(reader);
        ZmtpReaderSetID(reader, id);
        CSetAdd(cset, src_address, src_port, dst_address, dst_port, reader);
    } else {
        reader = (zmtpreader_t *) value;
    }
    ZmtpReaderPush(reader, data_start, data_len);

    return;

Error:
    fprintf(stderr, "Got error\n");
}

static void DestroyZmtpMapping(void *value, void *arg)
{
    zmtpreader_t *reader;

    printf("In DestroyZmtpMapping\n");
    reader = (zmtpreader_t *) value;
    assert(reader);
    ZmtpReaderDestroy(&reader);
}

static void
usage()
{
    fprintf(stderr, 
"zmtpdump\n"
"ZMTP packet analyzer\n"
"(C) 2015 Aleksandar Janicijevic aleks@vogonsoft.com\n"
"Usage: zmtpdump -i <interface> [ -vh ] <filter>\n"
"  -i <interface> - capture packets on specified interface\n"
"                   (e.g. lo or eth0)\n"
"  -v             - verbose - report TCP packets with flags,\n"
"                   such as SYN/ACK/PSH/RST\n"
"  -h             - this message\n"
"  <filter>       - filter that specifies what packets we capture\n"
"                   Examples:\n"
"                     - port 7001\n"
"                     - port 7001 or port 7002\n"
    );
    exit(0);
}

int
main(int argc, char *argv[])
{
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr header;
    char *filter;

    char *fl_interface = NULL;

// This is global.
//    int fl_verbose = 0;

    int fl_help = 0;
    int opt;

    while ((opt = getopt(argc, argv, "i:vh")) != -1) {
        switch (opt) {
            case 'i':
                fl_interface = strdup(optarg);
                break;
            case 'h':
                fl_help = 1;
                break;
            case 'v':
                fl_verbose = 1;
                break;
            default:
                usage();
        }
    }
    if (fl_help)
        usage();
    if (fl_verbose) printf("Verbose\n");
    if (optind == argc)
        usage();
    filter = argv[optind];
    printf("Filter: %s\n", filter);

    cset = CSetCreate();
    assert(cset);

    CSetSetDestructor(cset, DestroyZmtpMapping, NULL);

    if (fl_interface == NULL) { // Select default.
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Error: device %s unknown\n", dev);
            exit(2);
        }
    } else {
        dev = fl_interface;
    }

    printf("Interface: %s\n", dev);

    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(dev, &net, &mask, errbuf)) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    pcap_t *handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n",
            dev, errbuf);
        exit(2);
    }

    // Check if interface provides Ethernet data link.
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers\n",
            dev);
        exit(2);
    }

    // Compile filter.
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s\n", filter);
        exit(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter\n");
        exit(2);
    }

    pcap_loop(handle, -1, zmtp_handler, NULL);
    pcap_close(handle);
    free(fl_interface);

    return 0;
}
