This program will take in a name of a .pcap file and will sort out the packets
from it that do not meet the parameters specified. It will then print
the different headers for each packet remaining.

To run the program, use: python pktsniffer.py -r [file_name.pcap]

if you wish to add filters to it, you can use these flags as follows - 

-c [number] = the maximum number of packets to look through

-port [number] = the packets must have this port number to be displayed

-ip [string] = the packets must have this provided ip in either their
destination or send address

-proto [string] = the packets must have used this protocol to be included.
valid options are either tcp, udp or icmp


Examples of command line usage:

python pktsniffer.py -r data.pcap -c 5 -proto tcp

python pktsniffer.py -r data2.pcap -c 200 -port 80