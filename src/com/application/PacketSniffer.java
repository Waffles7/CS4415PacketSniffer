package com.application;

import com.sun.jna.Platform;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

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

    private static final HashMap<TCPTuple, ArrayList<Long>> openConnections = new HashMap<>();

    //Variable to decide how much delay over the average delay is considered enough to
    //possibly show a Man in the Middle attack
    private static final Long EXCESSIVE_DELAY = 100L;

    /*TODO: Figure out how to change values in an anonymous functions, they don't change from their
       initial value
     */
    private static final Long[] numPackets = {0L};
    private static final Long[] summedDelay = {0L};
    private static final Long[] averageDelay = {-1L};

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
        int snapshotLength = 65536; // in bytes
        int readTimeout = 50; // in milliseconds
        final PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);

        // Set a filter to only listen for tcp packets on port 80 (HTTP)
        String filter = "tcp port 80";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        // Create a listener that defines what to do with the received packets
        PacketListener listener = packet -> {
            boolean safe = true;
            StringBuilder builder = new StringBuilder();
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
                builder.append("IP Protocol: IPV6");
                builder.append("Source IP: ").append(header.getSrcAddr());
                builder.append("Destination IP: ").append(header.getDstAddr());
            }

            //Handle the TCP portion of the packet
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                TcpPacket.TcpHeader header = tcpPacket.getHeader();
                builder.append("Tertiary Protocol: TCP").append("\n");
                builder.append("Source Port: ").append(header.getSrcPort()).append("\n");
                builder.append("Destination Port: ").append(header.getDstPort()).append("\n");
            }

            //Handle the UDP portion of the packet
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                UdpPacket.UdpHeader header = udpPacket.getHeader();
                builder.append("Tertiary Protocol: UDP").append("\n");
                builder.append("Source Port: ").append(header.getSrcPort()).append("\n");
                builder.append("Destination Port: ").append(header.getDstPort()).append("\n");
            }

            TCPTuple tcpTuple = new TCPTuple(
                    tcpPacket.getHeader().getSrcPort(),
                    tcpPacket.getHeader().getDstPort(),
                    ipV4Packet.getHeader().getSrcAddr().getHostAddress(),
                    ipV4Packet.getHeader().getDstAddr().getHostAddress()
            );

            if (!openConnections.containsKey(tcpTuple)) {
                //No existing connection, add to existing
                openConnections.put(tcpTuple, new ArrayList<>());
            } else {
                //Check possible features for sign of an attack and remove if connection is finishing

                //Looking for average delay that is excessively long
                if (averageDelay[0] == -1L) {
                    Long mostRecent = openConnections.get(tcpTuple).get(openConnections.get(tcpTuple).size() - 1);
                    Long delay = System.currentTimeMillis() - mostRecent;
                    summedDelay[0] += delay;
                    numPackets[0]++;
                } else {
                    Long mostRecent = openConnections.get(tcpTuple).get(openConnections.get(tcpTuple).size() - 1);
                    Long delay = System.currentTimeMillis() - mostRecent;
                    if (delay - averageDelay[0] > EXCESSIVE_DELAY) {
                        safe = false;
                    }
                }

                //Looking for sequence numbers that are repeated.

                //Save more recent packet on a particular connection
                //Compare the new packet to the old, if repeated sequence then flag as a possible bad packet


                //Looking for sequence numbers that are out of order

                //Save old packet sequence numbers
                //Compare the new packet to the rest, if an old one re-appears then it's possible someone is
                //Attacking


                //Check if a packet is indicative of the end of a session, if so the packet needs to be removed from
                //The list of open connections.
//                if (condition) {
//                    openConnections.remove(tcpTuple);
//                }
            }

            if (safe) {
                System.out.println(builder.toString());
            } else {
                System.err.println(builder.toString());
            }
        };

        // Tell the handle to loop using the listener we created
        try {
            //TODO: Make larger for final submission.
            //Capture some packets to determine the average network delay
            handle.loop(10, listener);
            averageDelay[0] = summedDelay[0] / numPackets[0];
            //TODO: Make larger for final submission.
            //Capture packets infinitely
            handle.loop(10, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        //Only gets run if the packet looping finishes.
        PcapStat stats = handle.getStats();
        System.out.println("\n------------Final Stats for packet capture:------------");
        System.out.println("Average Packet delay over a TCP Connection: " + averageDelay[0]);
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