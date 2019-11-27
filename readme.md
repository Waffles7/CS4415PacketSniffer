This is a Packet Sniffer using Pcap4J Java Library to capture packets and display the relevant information to attempt to detect a Man in the Middle Attack.

## Prerequisites:

### WinPcap or libpcap
You need a packet capturing library installed. On Linux and Mac, libpcap is typically included by default, and if not, most distributions provide a package for easy installation. Absolute worst case, you will need to build it yourself from source from http://www.tcpdump.org. If using Windows, you need to install WinPcap(https://www.winpcap.org/install/default.htm) which provides a simple installer.

### Pcap4j libraries (from Maven)
org.pcap4j:pcap4j-packetfactory-static:1.7.52
org.pcap4j:pcap4j-packetfactory-propertiesbased:1.7.52
org.pcap4j:pcap4j-core:1.7.52
