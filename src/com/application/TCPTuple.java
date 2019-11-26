package com.application;

import org.pcap4j.packet.namednumber.TcpPort;

public class TCPTuple implements Comparable<TCPTuple> {

    private TcpPort sourcePort;
    private TcpPort destinationPort;
    private String sourceIP;
    private String destinationIP;

    public TCPTuple(TcpPort sourcePort, TcpPort destinationPort, String sourceIP, String destinationIP) {
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
    }

    @Override
    /*
     * Returns a 1 if false, a 0 if true.
     */
    public int compareTo(TCPTuple o) {
        if (!o.destinationPort.equals(this.destinationPort)) {
            return 1;
        }
        if (!o.sourcePort.equals(this.sourcePort)) {
            return 1;
        }
        if (!o.destinationIP.equalsIgnoreCase(this.destinationIP)) {
            return 1;
        }
        if (!o.sourceIP.equalsIgnoreCase(this.sourceIP)) {
            return 1;
        }
        return 0;
    }

    @Override
    public boolean equals(Object obj) {
        if ((obj == null) || (obj.getClass() != this.getClass())) {
            return false;
        }
        TCPTuple tcpTuple = (TCPTuple) obj;
        if (!tcpTuple.destinationPort.equals(this.destinationPort)) {
            return false;
        }
        if (!tcpTuple.sourcePort.equals(this.sourcePort)) {
            return false;
        }
        if (!tcpTuple.destinationIP.equalsIgnoreCase(this.destinationIP)) {
            return false;
        }
        return tcpTuple.sourceIP.equalsIgnoreCase(this.sourceIP);
    }
}
