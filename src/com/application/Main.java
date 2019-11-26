package com.application;

import com.sun.jna.Platform;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

public class Main {

    static PcapNetworkInterface getNetworkDevice() {
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
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);

        // Set a filter to only listen for tcp packets on port 80 (HTTP)
        //String filter = "tcp port 80";
        //handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

        // Create a listener that defines what to do with the received packets
        PacketListener listener = packet -> {
            // Print packet information to screen
            System.out.println("\n------------Packet Info:---------------");

            //Handle the Ethernet portion of the packet
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            if (ethernetPacket != null) {
                EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
                System.out.println("Protocol: " + ethernetHeader.getType());
            }

            //Handle the IP Portion of the information
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            if (ipV4Packet != null) {
                IpV4Packet.IpV4Header header = ipV4Packet.getHeader();
                System.out.println("Source IP: " + header.getSrcAddr());
                System.out.println("Destination IP: " + header.getDstAddr());
            }
            if (ipV6Packet != null) {
                IpV6Packet.IpV6Header header = ipV6Packet.getHeader();
                System.out.println("Source IP: " + header.getSrcAddr());
                System.out.println("Destination IP: " + header.getDstAddr());
            }

            //Handle the TCP portion of the packet
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                TcpPacket.TcpHeader header = tcpPacket.getHeader();
                System.out.println("Source Port: " + header.getSrcPort());
                System.out.println("Destination Port: " + header.getDstPort());
            }

            //Handle the UDP portion of the packet
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                UdpPacket.UdpHeader header = udpPacket.getHeader();
                System.out.println("Source Port: " + header.getSrcPort());
                System.out.println("Destination Port: " + header.getDstPort());
            }

        };

        // Tell the handle to loop using the listener we created
        try {
            //TODO: Make infinite for final submission.
            while (true) {
                handle.loop(10, listener);
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        PcapStat stats = handle.getStats();
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