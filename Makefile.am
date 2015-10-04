bin_PROGRAMS=zmtpdump test_zmtpdump sender receiver
zmtpdump_SOURCES=analyzetcp.c analyzezmtp.c buffer.c cset.c prog.c

test_zmtpdump_SOURCES=AllTests.c CuTest.c test_zmtp.c test_buffer.c \
  test_zhash.c analyzezmtp.c buffer.c cset.c analyzetcp.c test_tcp.c

sender_SOURCES=sender.c

receiver_SOURCES=receiver.c

check: test_zmtpdump
	./test_zmtpdump
