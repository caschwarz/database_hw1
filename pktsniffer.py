#imports
import argparse
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import rdpcap

"""
displays the requested details from the packets that have not already been filtered, such as each of the header types as 
well as the packet number
"""
def disp_packet_details(packets):
    #counter for number of packets
    packet_count=0

    #iterate over the remaining packets
    for packet in packets:
        #display packet title
        packet_count+=1
        print("Headers for packet number "+str(packet_count))
        print("")

        #displays the ether header
        if packet.haslayer(Ether):
            print(packet[Ether].summary())

        #displays the ip header
        if packet.haslayer(IP):
            print(packet[IP].summary())

        #displays the tcp header if exists
        if packet.haslayer(TCP):
            print(packet[TCP].summary())

        # displays the udp header if exists
        if packet.haslayer(UDP):
            print(packet[UDP].summary())

        # displays the icmp header if exists
        if packet.haslayer(ICMP):
            print(packet[ICMP].summary())

        print("")
    return

"""
this function removes packets from the packet list based on those packets properties and the arguments that the
user has given
"""
def limit_packets(protocol, packets, port, ip):
    #limit based on protocol
    if protocol is not None:
        for packet in packets:
            if packet.haslayer(IP):
                if not packet.haslayer(TCP) and protocol=='tcp':
                    packets.remove(packet)
                if not packet.haslayer(UDP) and protocol=='udp':
                    packets.remove(packet)
                if not packet.haslayer(ICMP) and protocol=='icmp':
                    packets.remove(packet)

    #limit packets based on port
    if port is not None:
        for packet in packets:
            if packet.haslayer(TCP):
                if packet[TCP].sport != port and packet[TCP].dport != port:
                    packets.remove(packet)
            elif packet.haslayer(UDP):
                if packet[UDP].sport != port and packet[UDP].dport != port:
                    packets.remove(packet)

    #limit packets based on ip
    if ip is not None:
        for packet in packets:
            if packet.haslayer(IP):
                if packet[IP].src!=ip and packet[IP].dst!=ip:
                    packets.remove(packet)

    #print remaining packet length
    print("Number of  packets remaining after filtering: "+str(len(packets)))

    #run the function to display the packet contents
    disp_packet_details(packets)
    return

"""
This function makes a list of all of the packets in the pcap file and then
passes that list to a function that sorts them
"""
def view_pcap(file, plimit, protocol, port, ip):
    #packets holds the list of packets from the pcap file
    packets = rdpcap(file)
    #reduces the packet list size to the limit size
    if plimit is not None:
        while len(packets)>plimit:
            packets.pop(len(packets)-1)
    #runs the function to limit the packets further
    limit_packets(protocol, packets, port, ip)
    return

"""
The main function takes the command line arguments and passes them into 
the view pcap function which continues the programs functionality
"""
def main():

    #this section parses command line arguments
    parser = argparse.ArgumentParser()
    #gets the name of the pcap file
    parser.add_argument("-r", type=str, help="name of .pcap file to analyze")
    #gets the maximum number of packets to analyze
    parser.add_argument("-c", type=int, help="limit of number of packets to analyze")
    #gets a type of protocol the user is filtering by
    parser.add_argument("-proto", type=str, help="type of protocol to filter on (tcp, udp or icmp)")
    #gets the port number a user wants to filter by
    parser.add_argument("-port", type=int, help="specify a port number to filter by")
    # gets the ip value a user is sorting by
    parser.add_argument("-ip", type=str, help="type the ip that you want to sort by")

    #save the arguments as variables
    args = parser.parse_args()
    file_name = args.r
    packet_limit=args.c
    protocol_filter=args.proto
    port=args.port
    ip=args.ip

    #print out the users selections to console
    print("Provided file name: "+file_name)
    if packet_limit is not None:
        print("Number of packets to analyze: "+str(packet_limit))
    if protocol_filter is not None:
        print("Returning packets with protocol type of: "+str(protocol_filter))
    if port is not None:
        print("Return packets with port number: "+str(port))
    if ip is not None:
        print("Getting packets that contain the ip: "+str(ip))

    #runs a function to open the pcap file and analyze it
    view_pcap(file_name, packet_limit, protocol_filter, port, ip)
    return

#starts program
if __name__=="__main__":
    main()