# zmtpdump, ZMTP packet analyzer

## Introduction

zmtpdump is a packet analyzer (also known as sniffer) of ZeroMQ Transport
Protocol. It currently supports ZMTP 3.0 only.

zmtpdump is meant to be used for the purpose of learning the low-level
details of ZeroMQ and for any time you need to analyze ZeroMQ communication,
for example when debugging.

Currently, zmtpdump runs and has been tested on Linux. Contributions for
other *nix flavors or other OSes are welcome.

## License

This project uses the MPL v2 license, see LICENSE.

### What zmtpdump does

zmtpdump listens on the specified network interface and ports and reports
on what information is exchanged, from establishment of connection to
exchanging messages.

### What zmtpdump does not do

* It does not support older versions of ZMTP (1.0 and 2.0).
* It does not currently support other security mechanism than NULL (ZMTP
specification mentions PLAIN and CURVE).
* It does not support other transports than TCP, such as Unix sockets.

## Building and installing

Build and install zmtpdump by doing this:

    ./configure
    make
    make install

Run unit test by executing

    make check

## Usage

Run zmtpdump without any parameters and it displays this help message:

```
zmtpdump
ZMTP packet analyzer
Usage: zmtpdump -i <interface> [ -vh ] <filter>
  -i <interface> - capture packets on specified interface
                   (e.g. lo or eth0)
  -v             - verbose - report TCP packets with flags,
                   such as SYN/ACK/PSH/RST
  -h             - this message
  <filter>       - filter that specifies what packets we capture
                   Examples:
                     - port 7001
                     - port 7001 or port 7002
```

For example, if you want to listen on loopback interface, ports 7001 and
7002, the command looks like this:

    sudo zmtpdump -i lo "port 7001 or port 7002"

The syntax for filter is the same as for the expression for tcpdump, which
is the syntax of pcap filters.

Note that zmtpdump has to be run as root or with sudo, because network
packet capturing is considered privileged operation.

## Contribution process

* C4 process is at http://rfc.zeromq.org/spec:16.
* All commits are be backed by issues.
* All commits are made as pull requests from forked work repository.

### Verbose flag

By default, zmtpdump works in non-verbose mode where it reports only ZMTP
information. If you want to see TCP packet flags for better understanding
of the connections, use -v flag. In verbose mode zmtpdump will report on
all TCP packets, so you can see as a TCP connection is being established
with three-way handshake (SYN-SYN/ACK-ASK) through to the connection
teardown (FIN-FIN/ACK-ACK).

You will probably want to use non-verbose mode most of the time, because
the verbose mode may flood you with packets that are not ZMTP packets.
Most significantly, in ZeroMQ the side that is doing the connect (as
opposed to bind) will attempt the connection many times per second, and if
the binding side is not currently running, you will see lots of
SYN-RST packet pairs.

## ZMTP

From ZMTP documentation:

A ZMTP connection goes through these main stages:

* The two peers agree on the version and security mechanism of the
connection by sending each other data and either continuing the
discussion, or closing the connection.
* The two peers handshake the security mechanism by exchanging zero or
more commands. If the security handshake is successful, the peers
continue the discussion, otherwise one or both peers closes the
connection.
* Each peer then sends the other metadata about the connection as a
final command. The peers may check the metadata and each peer decides
either to continue, or to close the connection.
* Each peer is then able to send the other messages. Either peer may at
any moment close the connection.

## Example of use with PUSH-PULL messages

As probably the simplest ZeroMQ pattern, let's look at a PUSH-PULL pair.
There are two programs running on the localhost, one (receiver)
creates a PULL socket and binds to port 7001 and the other one (sender)
creates a PUSH socket and connects to port 7001. After that the sender
sends a string message every 2 seconds. The messages that it sends are
numbers converted to strings: "1", "2", "3" and so on. (Note that it
doesn't send the terminating null byte, because ZeroMQ messages contain
the length of message. If the receiving side is a C program that wants to
use the received message as a string, it has to append the terminating null.)

The command to run zmtpdump is:

    sudo zmtpdump -v -i lo "port 7001"

We are running zmtpdump in verbose mode so we can show the TCP negotiation
alongside ZMTP packets.

Importantly, we start the receiver first, and the sender second. If we do
the opposite, everything will work, but the output of zmtpdump will show
a lot of junk before we start the receiver (SYN-RST/ACK message-response
pairs).

sender and receiver are included in this project, for basic test of
zmtpdump. The source files are sender.c and receiver.c, and both programs
are built together with zmtpdump executable and unit test test_zmtpdump
by invoking make.

Here is the output of zmtpdump:

```
Verbose
Filter: port 7001
Interface: lo
----------------------------
12:13:35.584
Packet size: 74 bytes
Payload size: 0 bytes
[127.0.0.1:47563, 127.0.0.1:7001] SYN 
----------------------------
12:13:35.584
Packet size: 74 bytes
Payload size: 0 bytes
[127.0.0.1:7001, 127.0.0.1:47563] SYN ACK 
----------------------------
12:13:35.584
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK 
----------------------------
12:13:35.584
Packet size: 76 bytes
Payload size: 10 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK PSH 
----------------------------
12:13:35.584
Packet size: 76 bytes
Payload size: 10 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK PSH 
----------------------------
12:13:35.584
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK 
----------------------------
12:13:35.584
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK 
----------------------------
12:13:35.584
Packet size: 67 bytes
Payload size: 1 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK PSH 
----------------------------
12:13:35.584
Packet size: 67 bytes
Payload size: 1 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK PSH 
----------------------------
12:13:35.584
Packet size: 119 bytes
Payload size: 53 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK PSH 
[127.0.0.1:7001, 127.0.0.1:47563]: Analyzing greeting
[127.0.0.1:7001, 127.0.0.1:47563]: Signature
[127.0.0.1:7001, 127.0.0.1:47563]: Version: 03.00
[127.0.0.1:7001, 127.0.0.1:47563]: Mechanism: NULL
[127.0.0.1:7001, 127.0.0.1:47563]: as-server: 0
[127.0.0.1:7001, 127.0.0.1:47563]: Filler
----------------------------
12:13:35.584
Packet size: 119 bytes
Payload size: 53 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK PSH 
[127.0.0.1:47563, 127.0.0.1:7001]: Analyzing greeting
[127.0.0.1:47563, 127.0.0.1:7001]: Signature
[127.0.0.1:47563, 127.0.0.1:7001]: Version: 03.00
[127.0.0.1:47563, 127.0.0.1:7001]: Mechanism: NULL
[127.0.0.1:47563, 127.0.0.1:7001]: as-server: 0
[127.0.0.1:47563, 127.0.0.1:7001]: Filler
----------------------------
12:13:35.585
Packet size: 94 bytes
Payload size: 28 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK PSH 
[127.0.0.1:7001, 127.0.0.1:47563]: READY command
[127.0.0.1:7001, 127.0.0.1:47563]: property: "Socket-Type" 53 6f 63 6b 65 74 2d 54 79 70 65
[127.0.0.1:7001, 127.0.0.1:47563]: value: "PULL" 50 55 4c 4c
----------------------------
12:13:35.585
Packet size: 94 bytes
Payload size: 28 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK PSH 
[127.0.0.1:47563, 127.0.0.1:7001]: READY command
[127.0.0.1:47563, 127.0.0.1:7001]: property: "Socket-Type" 53 6f 63 6b 65 74 2d 54 79 70 65
[127.0.0.1:47563, 127.0.0.1:7001]: value: "PUSH" 50 55 53 48
----------------------------
12:13:35.585
Packet size: 69 bytes
Payload size: 3 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK PSH 
[127.0.0.1:47563, 127.0.0.1:7001]: message: "1" 31
----------------------------
12:13:35.585
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK 
----------------------------
12:13:37.583
Packet size: 69 bytes
Payload size: 3 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK PSH 
[127.0.0.1:47563, 127.0.0.1:7001]: message: "2" 32
----------------------------
12:13:37.618
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK 
----------------------------
12:13:39.583
Packet size: 69 bytes
Payload size: 3 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK PSH 
[127.0.0.1:47563, 127.0.0.1:7001]: message: "3" 33
----------------------------
12:13:39.583
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK 
----------------------------
12:13:39.930
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK FIN 
----------------------------
12:13:39.930
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:7001, 127.0.0.1:47563] ACK FIN 
----------------------------
12:13:39.930
Packet size: 66 bytes
Payload size: 0 bytes
[127.0.0.1:47563, 127.0.0.1:7001] ACK 
```

Here you can see all packets, from the establishment of connection with
the three-way TCP handshake (SYN-SYN/ACK-ACK), through the negotiation and
message exchange, to closing of TCP connection.

In the above output, packet size is the size of the whole captured packet,
which includes ethernet header, IP header, TCP header and TCP payload.
Payload size is the size of payload data.

Note that there are some packets that have payload size greater than 0, but
no ZMTP packet is shown. That happens when the sending side sent some
bytes but zmtpdump has not seen a whole packet, so it will just buffer the
received data until it assembles a full ZMTP packet.

## Unit test

zmtpdump was developed TDD-style, bottom-up, starting with a buffer for
accumulating received bytes. The unit test reflects that and you can run
it by executing

    make check

Test data for unit test were collected using sender and receiver programs and
Wireshark.

## References

* ZMTP spec: http://zmtp.org/page:read-the-docs
* libpcap: http://www.tcpdump.org/pcap.html
* ZeroMQ home page: http://zeromq.org
* Wireshark: http://wireshark.org
