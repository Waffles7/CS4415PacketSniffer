package com.application;

import com.sun.jna.Platform;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

/**
 * Class to sniff packets on a network (Only tested on Windows with Wincap)
 * <p>
 * 5 required labels are present in the packet presentation
 * <p>
 * 3 features chosen to detect a MITM attack are:
 * - Out of order sequence numbers
 * - Repeated sequence numbers
 * - Excessive delay in packet transmission
 */
public class PacketSniffer {

    private static Long prevPacketTime = -1L;
    private static Long currentPacketTime = -1L;
    static Long delay = 0L;
    private static Long numPackets = 0L;
    private static Long excessiveDelay = 10000L;
    private static int prevSequenceNumber = -1;

    private static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

        // Get the network device
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);

        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        // Open the device and get a handle
        int snapshotLength = 94; // in bytes
        int readTimeout = 500; // in milliseconds
        final PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);

        // Set a filter to only listen for tcp packets on port 80 (HTTP)
        String filter = "tcp port 80";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        // Tell the handle to loop using the listener we created
        //TODO: Make larger for final submission.
        //Ping server to establish delay
        int i = 0;
        while (i < Integer.MAX_VALUE) {
            PcapPacket packet = handle.getNextPacket();
            if (packet != null) {
                StringBuilder builder = new StringBuilder();
                //Check for delay in timing, variation in Java running means this does not work perfectly
                if (prevPacketTime == -1L) {
                    prevPacketTime = System.nanoTime();
                } else if (excessiveDelay != -1L) {
                    currentPacketTime = prevPacketTime;
                    prevPacketTime = System.nanoTime();
                }
                if (currentPacketTime != -1L && prevPacketTime - currentPacketTime > excessiveDelay) {
                    builder.append("\nPacket flagged, possible Man in the middle attack! (excessive delay between packets)\n");
                }

                // Print packet information to screen

                builder.append("\n------------Packet Info:---------------\n");

                //Handle the Ethernet portion of the packet
                EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
                if (ethernetPacket != null) {
                    EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
                    builder.append("Main Protocol: ").append(ethernetHeader.getType()).append("\n");
                }

                //Handle the IP Portion of the information
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
                if (ipV4Packet != null) {
                    IpV4Packet.IpV4Header header = ipV4Packet.getHeader();
                    builder.append("IP Protocol: IPV4").append("\n");
                    builder.append("Source IP: ").append(header.getSrcAddr()).append("\n");
                    builder.append("Destination IP: ").append(header.getDstAddr()).append("\n");
                }
                if (ipV6Packet != null) {
                    IpV6Packet.IpV6Header header = ipV6Packet.getHeader();
                    builder.append("IP Protocol: IPV6 ").append("\n");
                    builder.append("Source IP: ").append(header.getSrcAddr()).append("\n");
                    builder.append("Destination IP: ").append(header.getDstAddr()).append("\n");
                }

                //Handle the TCP portion of the packet
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                if (tcpPacket != null) {
                    TcpPacket.TcpHeader header = tcpPacket.getHeader();
                    builder.append("Tertiary Protocol: TCP").append("\n");
                    builder.append("Source Port: ").append(header.getSrcPort()).append("\n");
                    builder.append("Destination Port: ").append(header.getDstPort()).append("\n");
                    //Find timestamp if exists
                    if (header.getOptions().size() > 7) {
                        builder.append("Timestamp: ").append(header.getOptions().get(8).getKind().valueAsString()).append("\n");
                    }
                    if (prevSequenceNumber != -1) {
                        if (prevSequenceNumber == header.getSequenceNumber()) {
                            builder.append("\nPacket flagged, possible Man in the middle attack! (repeated sequence number)\n");
                        }
                        prevSequenceNumber = header.getSequenceNumber();
                    } else {
                        prevSequenceNumber = header.getSequenceNumber();
                    }
                }

//            //Handle the UDP portion of the packet
//            UdpPacket udpPacket = packet.get(UdpPacket.class);
//            if (udpPacket != null) {
//                UdpPacket.UdpHeader header = udpPacket.getHeader();
//                builder.append("Tertiary Protocol: UDP").append("\n");
//                builder.append("Source Port: ").append(header.getSrcPort()).append("\n");
//                builder.append("Destination Port: ").append(header.getDstPort()).append("\n");
//            }
                System.out.println(builder.toString());
            }
            i++;
        }

        //TODO: Make larger for final submission.
        //Capture packets infinitely
        //handle.loop(10, listener);
        PcapStat stats = handle.getStats();

        //Only gets run if the packet looping finishes.
        System.out.println("\n------------Final Stats for packet capture:------------");
        System.out.println("Packets received: " + stats.getNumPacketsReceived());
        System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
        System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
        // Supported by WinPcap only
        if (Platform.isWindows()) {
            System.out.println("Packets captured: " + stats.getNumPacketsCaptured());
        }

        // Cleanup when complete
        handle.close();
    }
}