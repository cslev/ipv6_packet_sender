#!/usr/local/bin/python3

import argparse
from datetime import datetime
from time import sleep
from random import randint
from scapy.all import Ether,IPv6,TCP,Raw,sendp,send,sr1,srp1,ICMPv6DestUnreach

import sys #for OS errors
#import os.path
from pathlib import Path

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

parser.add_argument('-S','--src-ip', action="store", default="2603:c022:1:52dd:dead:beef:abba:edda", type=str, dest="src_ip" , help="Specify the source IPv6 address (default: 2603:c022:1:52dd:dead:beef:abba:edda)")
parser.add_argument('-D','--dst-ip', action="store", default="2405:800:9030:260d:7b47:dcff:1fec:c165", type=str, dest="dst_ip" , help="Specify the source IPv6 address (default: 2405:800:9030:260d:7b47:dcff:1fec:c165)")
parser.add_argument('-s','--src-port', action="store", default=randint(1,65535), type=str, dest="src_port", help="Specify the source port. Use 'random' to let the script generate a random source port for every packet sent (default: random but fixed for all packets)")
parser.add_argument('-d','--dst-port', action="store", default="179", type=str, dest="dst_port", help="Specify the (list of) destination port(s) via an integer or 'random' (or int,int,... without whitespaces). Use of 'random' in the list means that port will be random only. (Default: 179)")
parser.add_argument('-p','--payload', action="store", default=PAYLOAD_DEFAULT, type=str, dest="payload", help="Specify payload (default: random payload around 1500B)")
parser.add_argument('-P','--protocol', action="store", default="tcp_syn",dest="protocol",help="Specify layer-4 protocol (currently only tcp_syn is implemented)")
parser.add_argument('-n','--num-packets',action="store", default=1, dest="num_packets", type=int, help="Specify how many packets you want to send. It will be multiplied with the number of dst-port you set (default: 1)")
parser.add_argument('-i','--intf', action="store",default="ens3", dest="intf", type=str, help="Specify the interface to be used for sending (default: ens3)")
parser.add_argument('-o','--output', action="store",dest="output",default="responses.csv",help="Specify here the output file where the replied packets senders will be saved. Use in conjunction with -w, otherwise nothing is saved (default: responses.csv)")
# parser.add_argument('-r','--randomize_srcport', action="store_true", dest="randomize_srcport", help="Set this to True if random source ports are desired for each packet sent (default: False)")
# parser.add_argument('-R','--randomize_dstport', action="store_true", dest="randomize_dstport", help="Set this to True if random destination ports are desired for each packet sent (default: False)")

parser.add_argument('-w','--wait-for-response', action="store_true",dest="wait_for_response",help="Set this to true if you want to wait for any response within 2 seconds. Could be used for port discovery. (default: false)")
parser.add_argument('-t','--timeout', action="store",default=3, type=int, dest="timeout", help="Timeout for waiting for a response. Only make sense in conjunction with -w (default: 2)")
parser.add_argument('-v','--verbose', action="store_true",dest="verbose",help="Set this to true if you want verbose mode. (default: false)")


#set boolean default values
# parser.set_defaults(randomize_srcport=False)
parser.set_defaults(wait_for_response=False)
parser.set_defaults(verbose=False)


#parse arguments
results = parser.parse_args()
#get arguments accordingly from the results "dictionary"
SRC_IP=results.src_ip
DST_IP=results.dst_ip
SRC_PORT=results.src_port
RANDOMIZE_SRC_PORT=False
if SRC_PORT == "random": #randomized source ports for all packets
    RANDOMIZE_SRC_PORT=True
else:
    SRC_PORT = int(SRC_PORT)

#here, we don't match on random, it can be part of the list for which we generate a random port when sending the packet later on
DST_PORT=results.dst_port.split(',') #it works either with 1 element without ',' or with the list separated via ','
# for i,port in enumerate(DST_PORT):
#     DST_PORT[i]=port
print("DST ports to used: {}".format(DST_PORT))


PAYLOAD=results.payload
#check if protocol is supported
PROTOCOL=results.protocol
if PROTOCOL not in SUPPORTED_PROTOCOLS:
    print("{} is not supported (yet), please choose a protocol that is supported\n{}".format(PROTOCOL,SUPPORTED_PROTOCOLS))
    exit(-1)

NUM_PACKETS=results.num_packets
INTF=results.intf
# RANDOMIZE_SRC_PORT=results.randomize_srcport #create one random src port in the beginning that might be used for all packets
WAIT_FOR_RESPONSE=results.wait_for_response
TIMEOUT=int(results.timeout)
VERBOSE=results.verbose
OUTPUT=results.output

#open file in appending mode
my_file = Path(OUTPUT)
if my_file.is_file():
    # file exists
    print("{}Path to {} exists, open in append mode{}".format(yellow,OUTPUT,none))
    f = open(OUTPUT, "a")
else:
    print("{}Path to {} does not exists, initialize{}".format(yellow,OUTPUT,none))
    f = open(OUTPUT, "w")
    f.write("Alive host, discovered_by, timestamp\n")

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
start_time_date = datetime.now()
#for future use, we have some TCP flags here, but only S (SYN) is supported now
# TCP_FLAGS=["F","S","R","P","A","U","E","C"]



if RANDOMIZE_SRC_PORT: #do we want random source port?
    for n in range(0,NUM_PACKETS): #we generate n packets at the end
        #generate a packet with a random source port
        for dport in DST_PORT: #we now have a list of dst ports to play around with
            if dport == "random": #look for any request for a random port
                dport = randint(1,10000) #only the first 10000, those are probably service ports
            else: #treat the rest as integers
                dport = int(dport)

            if PROTOCOL == "tcp_syn":
                print("Sending packet to {}{} ({}){}".format(yellow,
                                                            DST_IP,
                                                            dport,
                                                            none))
                PACKET=assemble_ipv6_tcp_packet(src_ip=SRC_IP,
                                            dst_ip=DST_IP,
                                            src_port=randint(1,65535),
                                            dst_port=dport,
                                            payload=PAYLOAD,
                                            tcp_flag="S")
                if WAIT_FOR_RESPONSE:
                    print("...waiting for response for {} seconds".format(TIMEOUT))
                    resp=srp1(PACKET,timeout=TIMEOUT,iface=INTF)
                    if resp:
                        timestamp_discovery = datetime.now()

                        print("{}{}|--{}{}Someone has responded from {}{} dst port {}{}".format(
                                bold,
                                green,
                                none,
                                bold,
                                green,
                                DST_IP,
                                dport,
                                none))
                        if(ICMPv6DestUnreach in resp):
                            print("{}{}|-----> ICMP packet  - dest-host unreachable{}".format(bold,yellow,none))
                            print("{}{}|--------> Answered by: {}{}".format(bold,yellow,resp[IPv6].src,none))
                            f.write(str("{},{},{}\n".format(resp[IPv6].src, "ICMPDestUnreach",timestamp_discovery)))
                        else:
                            #it is not ICMPv6 Dest unreachable, so probably TCP reset
                            #@TODO: make it definite instead of probable
                            if(TCP in resp): #at least the response is TCP
                                print("{}{}|-----> TCP response from {}{}".format(bold,blue,resp[IPv6].src,none))
                                print("{}{}|-------> TCP-flags: {}{}".format(bold,blue,resp[TCP].flags,none))
                                f.write(str("{},{},{}\n".format(resp[IPv6].src, "TCP-closed-port", timestamp_discovery)))
                            
                            
                        if (VERBOSE):
                            print("{}-----------------------{}".format(green,none))
                            print("{}{}{}".format(green,resp,none))
                            resp.show()
                            print("{}-----------------------{}".format(green,none))
                            

                else:
                    send_packet(PACKET,INTF)
            
else:
    #create one packet and send as many times needed 
    for n in range(0,NUM_PACKETS):
        for dport in DST_PORT: #we now have a list of dst ports to play around with
            if dport == "random": #look for any request for a random port
                dport = randint(1,10000) #only the first 10000, those are probably service ports
            else: #treat the rest as integers
                dport = int(dport)

            if PROTOCOL == "tcp_syn":
                PACKET=assemble_ipv6_tcp_packet(src_ip=SRC_IP,
                                                dst_ip=DST_IP,
                                                src_port=SRC_PORT,
                                                dst_port=dport,
                                                payload=PAYLOAD,
                                                tcp_flag="S")
                if WAIT_FOR_RESPONSE:
                    print("...waiting for response for {} seconds".format(TIMEOUT))
                    resp=srp1(PACKET,timeout=TIMEOUT,iface=INTF)
                    if resp:
                        timestamp_discovery = datetime.now()

                        print("{}{}|--{}{}Someone has responded from {}{} dst port {}{}".format(
                                bold,
                                green,
                                none,
                                bold,
                                green,
                                DST_IP,
                                dport,
                                none))
                        if(ICMPv6DestUnreach in resp):
                            print("{}{}|-----> ICMP packet  - dest-host unreachable{}".format(bold,yellow,none))
                            print("{}{}|--------> Answered by: {}{}".format(bold,yellow,resp[IPv6].src,none))
                            f.write(str("{},{},{}\n".format(resp[IPv6].src, "ICMPDestUnreach",timestamp_discovery)))
                        else:
                            #it is not ICMPv6 Dest unreachable, so probably TCP reset
                            #@TODO: make it definite instead of probable
                            if(TCP in resp): #at least the response is TCP
                                print("{}{}|-----> TCP response from {}{}".format(bold,blue,resp[IPv6].src,none))
                                print("{}{}|-------> TCP-flags: {}{}".format(bold,blue,resp[TCP].flags,none))
                                f.write(str("{},{},{}\n".format(resp[IPv6].src, "TCP-port-closed", timestamp_discovery)))
                            
                        
                        if (VERBOSE):
                            print("{}-----------------------{}".format(green,none))
                            print("{}{}{}".format(green,resp,none))
                            resp.show()
                            print("{}-----------------------{}".format(green,none))
                else:
                    send_packet(PACKET,INTF)

end_time_date = datetime.now()
f.close()
print("Time required for sending the packets: {}".format(end_time_date-start_time_date))
