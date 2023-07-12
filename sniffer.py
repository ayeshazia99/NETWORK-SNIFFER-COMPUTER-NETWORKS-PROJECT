from scapy.all import *
import re

def getProtocol(protocolNr):
    protocolFile = open('Protocol.txt', 'r')
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(protocolNr), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return "No such Protocol."

# function to get the type of service field in the ip header (8 bits long)
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC?ECP", 6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1
    
    tabs = '\n\t\t\t'    #for new line
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TOS

#function to get the flags value
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if neccessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'     #for new line
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags

def process_packet(packet):
    # Extract IP header fields
    version = packet[IP].version
    IHL = packet[IP].ihl
    TOS = packet[IP].tos
    TOS = getTOS(TOS)
    totalLength = packet[IP].len
    ID = packet[IP].id
    flags = packet[IP].flags
    flags = getFlags(flags)
    fragmentOffset = packet[IP].frag & 0x1FFF
    TTL = packet[IP].ttl
    protocolNr = packet[IP].proto
    protocol = getProtocol(protocolNr)
    checksum = packet[IP].chksum
    sourceAddress = packet[IP].src
    destinationAddress = packet[IP].dst
    
    if Raw in packet:
        data = packet[Raw].load
    else:
        data = ""

    
    if protocolNr == 6:  # TCP protocol
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        if dst_port == 80 or dst_port == 8080:  # HTTP ports
            print(f"HTTP packet from {sourceAddress}:{src_port} to {destinationAddress}:{dst_port}")
        elif dst_port == 443:  # HTTPS port
            print(f"HTTPS packet from {sourceAddress}:{src_port} to {destinationAddress}:{dst_port}")
        elif dst_port==587 or dst_port==465 or dst_port==25:  # SMTP port
            print(f"SMTP packet from {sourceAddress} to {destinationAddress}")
        elif dst_port == 21:  # FTP port
            print(f"FTP packet from {sourceAddress} to {destinationAddress}")
        else:
            print(f"TCP packet from {sourceAddress}:{src_port} to {destinationAddress}:{dst_port}")
    elif protocolNr == 17:  # UDP protocol
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if dst_port == 53 or dst_port == 53:  # HTTP ports
            print(f"DNS packet from {sourceAddress}:{src_port} to {destinationAddress}:{dst_port}")
        print(f"UDP packet from {sourceAddress}:{src_port} to {destinationAddress}:{dst_port}")
    else:
        print(f"Unknown protocol {protocolNr}")

    # Print IP header details and payload
    print(f"\n\nAn IP packet with size {totalLength} was captured.")
    print("Raw Data: ", data)
    print("\nParsed Data")
    print("Version:\t\t" + str(version))
    print("Header Length:\t\t" + str(IHL*4) + " bytes")
    print("Type of Service:\t" + str(TOS))
    print("Length:\t\t\t" + str(totalLength))
    print("ID:\t\t\t" + str(hex(ID)) + ' (' + str(ID) + ' )')
    print("Flags:\t\t\t" + str(flags))
    print("Fragment Offset:\t" + str(fragmentOffset))
    print("TTL:\t\t\t" + str(TTL))
    print("Protocol:\t\t" + str(protocol) + " (" + str(protocolNr) + ")")
    print("Checksum:\t\t" + str(checksum))
    print("Source IP Address:\t" + sourceAddress)
    print("Destination IP Address:\t" + destinationAddress)
    print("Payload:\n", data[20:])

#sniff(filter="ip", prn=process_packet)
# get user input for protocol type
protocol_filter = input("Enter protocol type (tcp/udp/smtp/ftp/http/https/dns): ")

# sniff packets based on user input for protocol type
if protocol_filter == 'tcp':
    sniff(filter="tcp", prn=process_packet)
elif protocol_filter == 'udp':
    sniff(filter="udp and ip", prn=process_packet)
elif protocol_filter == 'dns':
    sniff(filter="udp dst port 53", prn=process_packet)
elif protocol_filter == 'smtp':
    sniff(filter="tcp dst port 25", prn=process_packet)
elif protocol_filter == 'ftp':
    sniff(filter="tcp dst port 21", prn=process_packet)
elif protocol_filter == 'http':
    sniff(filter="(tcp dst port 80) and ip", prn=process_packet)
elif protocol_filter == 'https':
    sniff(filter="(tcp dst port 443) and ip", prn=process_packet)    
else:
    print("Invalid protocol type")
#sniff(filter="(tcp dst port 443) and ip", prn=process_packet)    #to filter https packets only
#sniff(filter="(tcp dst port 80) and ip", prn=process_packet)  #to filter http packets only
#sniff(filter="udp and ip", prn=process_packet)
#sniff(filter="(tcp dst port 25) and ip", prn=process_packet)   #to filter smtp packets only
#sniff(filter="(tcp dst port 21) and ip", prn=process_packet)   #to filter ftp packets only