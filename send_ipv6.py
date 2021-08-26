#!/usr/local/bin/python3

import argparse
from datetime import datetime
from time import sleep
from random import randint
from scapy.all import IPv6,TCP,Raw,sendp,send

import sys #for OS errors

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

# parser for the command line args
parser = argparse.ArgumentParser(description="Craft IPv6 packet and send", formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-a','--src-ip', action="store", default="2603:c022:1:52dd:dead:beef:abba:edda", type=str, dest="src_ip" , help="Specify the source IPv6 address (default: 2603:c022:1:52dd:dead:beef:abba:edda)")
parser.add_argument('-b','--dst-ip', action="store", default="2405:800:9030:260d:7b47:dcff:1fec:c165", type=str, dest="dst_ip" , help="Specify the source IPv6 address (default: 2405:800:9030:260d:7b47:dcff:1fec:c165)")
parser.add_argument('-c','--src-port', action="store", default=randint(1,65535), type=int, dest="src_port", help="Specify the source port (default: random)")
parser.add_argument('-d','--dst-port', action="store", default=179, type=int, dest="dst_port", help="Specify the destination port (default: 179)")
parser.add_argument('-e','--payload', action="store", default=PAYLOAD_DEFAULT, type=str, dest="payload", help="Specify payload (default: random payload around 1500B)")
parser.add_argument('-f','--tcp-syn', action="store_true", dest="tcp_syn",help="Specify whether to use TCP-SYN (default: YES (no other feature is implemented yet)")
parser.add_argument('-g','--num-packets',action="store", default=1, dest="num_packets", type=int, help="Specify how many packets you want to send (default: 1)")
parser.add_argument('-i','--intf', action="store",default="ens3", dest="intf", type=str, help="Specify the interface to be used for sending (default: ens3)")
parser.add_argument('-j','--randomize_srcport', action="store_true", dest="randomize_srcport", help="Set this to True if random source ports are desired for each packet sent (default: True)")


#set boolean default values
parser.set_defaults(tcp_syn=True)
parser.set_defaults(randomize_srcport=True)

results = parser.parse_args()

SRC_IP=results.src_ip
DST_IP=results.dst_ip
SRC_PORT=results.src_port
DST_PORT=results.dst_port
PAYLOAD=results.payload
TCP_SYN=results.tcp_syn
NUM_PACKETS=results.num_packets
INTF=results.intf
RANDOMIZE_SRC_PORT=results.randomize_srcport



# We don't need this printout as packet.show() will show all details later
# print("#### Set parameters:\n")
# print("SRC IP: {}".format(SRC_IP))
# print("DST IP: {}".format(DST_IP))
# print("SRC PORT: {}".format(SRC_PORT))
# print("DST PORT: {}".format(DST_PORT))
# print("TCP SYN: {}".format(TCP_SYN))
# print("PAYLOAD: {}".format(PAYLOAD))
# print("#### ------- ####\n")


def assemble_ipv6_packet(src_ip,dst_ip,src_port,dst_port,payload):
    '''
    This function assembles an IPv6 packet
    '''
    IP_HEADER=IPv6(src=src_ip,dst=dst_ip)
    TCP_HEADER=TCP(sport=src_port,dport=dst_port,flags="S")
    PAYLOAD=Raw(payload)
    p=IP_HEADER/TCP_HEADER/PAYLOAD
    p.show()

    return p


def send_packet(packet, iface=INTF):
    '''
    This function sends a crafted ipv6 packet on an IPv6 enabled interface 
    '''
    try:
        print("send packet on iface {}".format(iface))
        sendp(packet,iface=iface)
    except OSError as e:
        print("Could not sent packet...maybe your interface is not IPv6-enabled?")
        print("Error message below")
        print("-----------------------------------")
        print(e)

# IP_HEADER.show()


if(not TCP_SYN):
    print("Only TCP SYN packets are supported now! Exiting")
    exit(-1)


PACKET=assemble_ipv6_packet(SRC_IP,DST_IP,SRC_PORT,DST_PORT,PAYLOAD)
print("Example packet")
PACKET.show()


print("Sending packets...")
start_time_date = datetime.now()

# start_time = start_time_date.strftime("%H:%M:%S")
# print("Start Time =", start_time)
# sleep(1)
# end_time_date = datetime.now()
# end_time = end_time_date.strftime("%H:%M:%S")
# print("End Time =", end_time)
# print(end_time_date-start_time_date)



if RANDOMIZE_SRC_PORT:
    for n in range(0,NUM_PACKETS):
        #generate a packet with a random source port 
        PACKET=assemble_ipv6_packet(SRC_IP,DST_IP,randint(1,65535),DST_PORT,PAYLOAD)
        send_packet(PACKET,INTF)
        
else:
    #create one packet and send as many times needed
    PACKET=assemble_ipv6_packet(SRC_IP,DST_IP,SRC_PORT,DST_PORT,PAYLOAD)
    for n in range(0,NUM_PACKETS):
        send_packet(PACKET,INTF)


end_time_date = datetime.now()

print("Time required for sending the packets: {}".format(end_time_date-start_time_date))