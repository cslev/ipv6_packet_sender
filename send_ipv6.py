#!/usr/local/bin/python3

import argparse
from datetime import datetime
from time import sleep
from random import randint
from scapy.all import Ether,IPv6,TCP,Raw,sendp,send,sr1,srp1

import sys #for OS errors

# COLORIZING
none = '\033[0m'
bold = '\033[01m'
disable = '\033[02m'
underline = '\033[04m'
reverse = '\033[07m'
strikethrough = '\033[09m'
invisible = '\033[08m'

black = '\033[30m'
red = '\033[31m'
green = '\033[32m'
orange = '\033[33m'
blue = '\033[34m'
purple = '\033[35m'
cyan = '\033[36m'
lightgrey = '\033[37m'
darkgrey = '\033[90m'
lightred = '\033[91m'
lightgreen = '\033[92m'
yellow = '\033[93m'
lightblue = '\033[94m'
pink = '\033[95m'
lightcyan = '\033[96m'
CBLINK = '\33[5m'
CBLINK2 = '\33[6m'
# ------ =================================== -----

PAYLOAD_DEFAULT="asdasdasdasdadasdasdasdasdasdasdasdasdasdasdasssssssssssssasdddddddddddddddddddddd" \
"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddsadssss" \
"sssssssssssssssssssssssssssssssssssssss3efdsgwrsdgsidfgjkdflsnhdflkhndflkngfdklsgnkfdlngkl" \
"dfsngkldsfngkledsfnhkdfnshlkdsgnfhkfsdngkldfsnhdklfshndksflhndfklshndklsfnhdfklshndfklshnd" \
"fklshdskjfasldkgjklasgjaklfsjgklsajgklsdjgksldjglkasdjglksdajglkasdjgklsajdgkljsdklgjsdklg" \
"jkldsajgklsadjgklasdjgklasdjglaksdjgklasjdgklsadjgklsdjgklsadjglkasjglksdjgklsajdgklajsdgk" \
"ljasdklgjaskldjgksladjgklsdjgklsdjgklsdjgklsdjgklasgjaslkgjsklajgkdlsjgklsajgklsdjgklsdjgk" \
"lsjgklsdjgkldsjgklasdjgklsfjdglkfajgldsgjksfdjgkdsjglksfgjkalfsjgkldsjgsdklafjkdlsjgkldsjg" \
"kldsajgklasdjgklsdjgkldsjgklasjgklsdjgklsadjglkasjglajsldgksadlgjalsdkjgaklsdjglkasdjgklas" \
"jdgksg;aero;idfjglkdfjgskldgjaskdlfjsdklagjskladzgjkasdlut4wiortj384erty7ru8eoisautdj489qw" \
"aeothisdfjalewishdfauilsdkgzhjvlauirsdkzhgjskjzddshfjkdsahfsoiaudghiow4ehsdliasdngiworalsd" \
"nalirsdfhawdglszvisdzhgioradlshgliasdhgisoadlhgiosdalhzgosiadghlisladolghzilsadzhgisd;lhfg" \
";alihg;sldiahgkl;sadh;klasdhgklsadhg;klsadhg;klashdgkl;dshaglskdjflksdjfkldsjfklasdjgkldsj" \
"gklsajglkdsjgklasdjgkldsgjklasjdgklasdjgklsadjgklsadjgklsadjgklsdjgaslkdgjaa4liwjt4iglwjrk" \
"sgjl;gjiershifldhfdis;luirsutisdjgdlsigj;asiljidsgja;sigjfidgjsdigsiadlgjds;igjasid;lgjriy" \
"3905a4erutgjsd;oizlnvijgraogjfdgdjspogjfidsdssdsdsdssdsdddddd12345678901234567891222222223" \
"23"

SUPPORTED_PROTOCOLS = ['tcp_syn']

# parser for the command line args
parser = argparse.ArgumentParser(description="Craft IPv6 packet and send", formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-a','--src-ip', action="store", default="2603:c022:1:52dd:dead:beef:abba:edda", type=str, dest="src_ip" , help="Specify the source IPv6 address (default: 2603:c022:1:52dd:dead:beef:abba:edda)")
parser.add_argument('-b','--dst-ip', action="store", default="2405:800:9030:260d:7b47:dcff:1fec:c165", type=str, dest="dst_ip" , help="Specify the source IPv6 address (default: 2405:800:9030:260d:7b47:dcff:1fec:c165)")
parser.add_argument('-c','--src-port', action="store", default=randint(1,65535), type=int, dest="src_port", help="Specify the source port (default: random)")
parser.add_argument('-d','--dst-port', action="store", default="179", type=str, dest="dst_port", help="Specify the (list of) destination port(s) via an integer (or int,int,... without whitespaces) (default: 179)")
parser.add_argument('-e','--payload', action="store", default=PAYLOAD_DEFAULT, type=str, dest="payload", help="Specify payload (default: random payload around 1500B)")
parser.add_argument('-f','--protocol', action="store", default="tcp_syn",dest="protocol",help="Specify layer-4 protocol (currently only tcp_syn is implemented)")
parser.add_argument('-g','--num-packets',action="store", default=1, dest="num_packets", type=int, help="Specify how many packets you want to send. It will be multiplied with the number of dst-port you set (default: 1)")
parser.add_argument('-i','--intf', action="store",default="ens3", dest="intf", type=str, help="Specify the interface to be used for sending (default: ens3)")
parser.add_argument('-j','--randomize_srcport', action="store_true", dest="randomize_srcport", help="Set this to True if random source ports are desired for each packet sent (default: False)")
parser.add_argument('-m','--wait-for-response', action="store_true",dest="wait_for_response",help="Set this to true if you want to wait for any response within 2 seconds. Could be used for port discovery. (default: false)")


#set boolean default values
parser.set_defaults(randomize_srcport=False)
parser.set_defaults(wait_for_response=False)

#parse arguments
results = parser.parse_args()
#get arguments accordingly from the results "dictionary"
SRC_IP=results.src_ip
DST_IP=results.dst_ip
SRC_PORT=results.src_port
DST_PORT=results.dst_port.split(',') #it works either with 1 element without ',' or with the list separated via ','
#convert ports to int
for i,port in enumerate(DST_PORT):
    DST_PORT[i]=int(port)
print("DST ports to used: {}".format(DST_PORT))
PAYLOAD=results.payload
#check if protocol is supported
PROTOCOL=results.protocol
if PROTOCOL not in SUPPORTED_PROTOCOLS:
    print("{} is not supported (yet), please choose a protocol that is supported\n{}".format(PROTOCOL,SUPPORTED_PROTOCOLS))
    exit(-1)

NUM_PACKETS=results.num_packets
INTF=results.intf
RANDOMIZE_SRC_PORT=results.randomize_srcport
WAIT_FOR_RESPONSE=results.wait_for_response



# We don't need this printout as packet.show() will show all details later
# print("#### Set parameters:\n")
# print("SRC IP: {}".format(SRC_IP))
# print("DST IP: {}".format(DST_IP))
# print("SRC PORT: {}".format(SRC_PORT))
# print("DST PORT: {}".format(DST_PORT))
# print("TCP SYN: {}".format(TCP_SYN))
# print("PAYLOAD: {}".format(PAYLOAD))
# print("#### ------- ####\n")


def assemble_ipv6_tcp_packet(src_ip,
                            dst_ip,
                            src_port=randint(1024,65535),
                            dst_port=179,
                            payload=PAYLOAD_DEFAULT, 
                            tcp_flag="S"
                        ):
    '''
    This function assembles an IPv6 packet by the header and payload data supplied
    '''
    #play around with MAC addresses here - we just use defaults without setting specific SRC or DST
    ETHER=Ether() 

    #creating the IPv6 header from the addresses supported
    IP_HEADER=IPv6(src=src_ip,dst=dst_ip)

    #TCP header - create using the ports supplied and set syn flag
    TCP_HEADER=TCP(sport=src_port,dport=dst_port,flags=tcp_flag)

    #create RAW payload from the payload string
    PAYLOAD=Raw(payload)

    #assemble the packet
    p=ETHER/IP_HEADER/TCP_HEADER/PAYLOAD
#    p.show()

    return p


def send_packet(packet, iface=INTF):
    '''
    This function sends a crafted ipv6 packet on an IPv6 enabled interface 
    '''
    try:
        print("sendp packet on iface {}".format(iface))
        sendp(packet,iface=iface)

    except OSError as e:
        print("Could not sent packet...maybe your interface is not IPv6-enabled?")
        print("Error message below")
        print("-----------------------------------")
        print(e)




# PACKET=assemble_ipv6_tcp_packet(SRC_IP,DST_IP,SRC_PORT,DST_PORT,PAYLOAD)
# print("Example packet")
# PACKET.show()
print("Sending packets...")
start_time_date = datetime.now()
#for future use, we have some TCP flags here, but only S (SYN) is supported now
# TCP_FLAGS=["F","S","R","P","A","U","E","C"]

if RANDOMIZE_SRC_PORT: #do we want random source port?
    for n in range(0,NUM_PACKETS): #we generate n packets at the end
        #generate a packet with a random source port
        for dport in DST_PORT: #we now have a list of dst ports to play around with
            if PROTOCOL == "tcp_syn":
                PACKET=assemble_ipv6_tcp_packet(src_ip=SRC_IP,
                                            dst_ip=DST_IP,
                                            src_port=randint(1,65535),
                                            dst_port=dport,
                                            payload=PAYLOAD,
                                            tcp_flag="S")
                if WAIT_FOR_RESPONSE:
                    resp=srp1(PACKET,timeout=2,iface=INTF)
                    if resp:
                        print("{}{}|--{}{}Someone has responded from {}{} dst port {}{}".format(
                                bold,
                                green,
                                none,
                                bold,
                                green,
                                DST_IP,
                                dport,
                                none))
                else:
                    send_packet(PACKET,INTF)
            
else:
    #create one packet and send as many times needed 
    for n in range(0,NUM_PACKETS):
        for dport in DST_PORT: #we now have a list of dst ports to play around with
            if PROTOCOL == "tcp_syn":
                PACKET=assemble_ipv6_tcp_packet(src_ip=SRC_IP,
                                                dst_ip=DST_IP,
                                                src_port=SRC_PORT,
                                                dst_port=dport,
                                                payload=PAYLOAD,
                                                tcp_flag="S")
                if WAIT_FOR_RESPONSE:
                    resp=srp1(PACKET,timeout=2,iface=INTF)
                    if resp:
                        print("{}{}|--{}{}Someone has responded from {}{} dst port {}{}".format(
                                bold,
                                green,
                                none,
                                bold,
                                green,
                                DST_IP,
                                dport,
                                none))
                else:
                    send_packet(PACKET,INTF)

end_time_date = datetime.now()

print("Time required for sending the packets: {}".format(end_time_date-start_time_date))
