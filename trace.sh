# Make
make clean
make

# PingTest
./trace Program1_Trace/TestTraces/PingTest.pcap > MyTestTraces/myPing.out

# ArpTest
./trace Program1_Trace/TestTraces/ArpTest.pcap > MyTestTraces/myArp.out

# IP Bad Checksum
./trace Program1_Trace/TestTraces/IP_bad_checksum.pcap > MyTestTraces/myIPbad.out

# UDP file
./trace Program1_Trace/TestTraces/UDPfile.pcap > MyTestTraces/myUDP.out

# Small TCP
./trace Program1_Trace/TestTraces/smallTCP.pcap > MyTestTraces/mySmallTCP.out

# HTTP
./trace Program1_Trace/TestTraces/Http.pcap > MyTestTraces/myHTTP.out

# TCP Bad Checksum
./trace Program1_Trace/TestTraces/TCP_bad_checksum.pcap > MyTestTraces/myTCPbad.out

# Large Mix
./trace Program1_Trace/TestTraces/largeMix.pcap > MyTestTraces/myLargeMix.out

# Large Mix 2
./trace Program1_Trace/TestTraces/largeMix2.pcap > MyTestTraces/myLargeMix2.out
