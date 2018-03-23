#!/bin/python
import logging
import time
import inspect
import lorem as loremipsum
from math import ceil
from datetime import datetime

# Change log level to suppress annoying IPv6 error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

PCAP_FILE_NAME = 'dump.pcap'

INITIAL_SEQ_SERVER = 1000
SeqNrServer = INITIAL_SEQ_SERVER
INITIAL_ID_SERVER = 2000
LastIdServer = INITIAL_ID_SERVER

Timestamp = time.time()


def write(pkt, delay=5):
    global Timestamp

    Timestamp += 5

    # appends packet to output file
    pkt.time = Timestamp
    wrpcap(PCAP_FILE_NAME, pkt, append=True)


def increaseID(ip):
    ip.fields.update({'id': (ip.fields.get('id')+1) % 65536})


def generateHTTPTraffic(source, destination, port, ressource, delay=5):
    global SeqNrServer, LastIdServer

    # initialize seq for the client
    SeqNrClient = int(RandNum(0, 2**32))

    ipClient = IP(dst=str(destination), src=str(source))
    ipServer = IP(dst=str(source), src=str(destination))

    ipClient.fields.update({'id': int(RandNum(0, 65535))})
    ipServer.fields.update({'id': LastIdServer})

    # Generate random source port number
    portSrc = int(RandNum(1024, 65535))

    # Create SYN packet and write it to PCAP
    SYN = ipClient/TCP(sport=portSrc, dport=port, flags="S", seq=SeqNrClient)
    write(SYN, delay)
    increaseID(ipClient)

    # SYNACK response from the server
    SYNACK = ipServer/TCP(sport=port, dport=portSrc,
                          flags="SA", seq=SeqNrServer, ack=SYN.seq+1)
    write(SYNACK, delay)
    increaseID(ipServer)

    # ACK from the client
    ACK = ipClient/TCP(sport=portSrc, dport=port, flags="A",
                       seq=SYNACK.ack, ack=SYNACK.seq + 1)
    write(ACK, delay)
    increaseID(ipClient)

    # Prepare GET statement
    get = 'GET /'+ressource+' HTTP/1.0\n\n'

    # GET request (ack, psh) from the client
    # psh = send data to the application
    PSH_GET = ipClient/TCP(sport=portSrc, dport=port,
                           flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)/get
    write(PSH_GET, delay)
    increaseID(ipClient)

    # ACK from the server, GET request is received,
    ACK = ipServer/TCP(sport=port, dport=portSrc, flags="A",
                       seq=PSH_GET.ack, ack=PSH_GET.seq + len(get))
    write(ACK, delay)
    increaseID(ipServer)

    # Generate custom http file content.
    ACK_no_html = ipServer/TCP(sport=port, dport=portSrc, flags="PA", seq=PSH_GET.ack,
                               ack=PSH_GET.seq + len(get))

    lorem = loremipsum.text() + loremipsum.text()

    response = "<html><body><h1>Here is the page " + \
        ressource + " !</h1><p>" + lorem + "</p></body></html>"
    html1 = "HTTP/1.1 200 OK\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: " + \
        str(len(response)) + "\x0d\x0a\x0d\x0a" + response

    mtu = 1500
    packet_size = len(ACK_no_html)
    max_data_length = mtu - packet_size

    if len(html1) <= packet_size:
        # GET response (ack, psh) from the server
        PSH_ACK = ACK_no_html / html1

        write(PSH_ACK, delay)
        increaseID(ipServer)

        # ACK from the client, GET response received by the client
        ACK = ipClient/TCP(sport=portSrc, dport=port, flags="A",
                           seq=PSH_ACK.ack, ack=PSH_ACK.seq + len(html1))
        write(ACK, delay)
        increaseID(ipClient)

        # FIN, ACK from the client, the client ask to end connection
        FIN_ACK = ipClient/TCP(sport=portSrc, dport=port, flags="FA",
                               seq=PSH_ACK.ack, ack=PSH_ACK.seq + len(html1))
        write(FIN_ACK, delay)
        increaseID(ipClient)

    else:
        # for each part of the message
        last_packet_client = PSH_GET
        nb_chunk = ceil(len(html1)/max_data_length)

        for i in range(0, nb_chunk):

            # if first paquet, seq use length of the get request
            if i == 0:
                ACK_no_html = ipServer/TCP(sport=port, dport=portSrc, flags="A", seq=last_packet_client.ack,
                                           ack=last_packet_client.seq + len(get))
            # if  0 < i < last : send ACK
            elif i < nb_chunk - 1:
                ACK_no_html = ipServer/TCP(sport=port, dport=portSrc, flags="A", seq=last_packet_client.ack,
                                           ack=last_packet_client.seq)
            # if last packet : send PUSH, ACK
            else:
                ACK_no_html = ipServer/TCP(sport=port, dport=portSrc, flags="PA", seq=last_packet_client.ack,
                                           ack=last_packet_client.seq)

            substring = html1[i*max_data_length:(i+1)*max_data_length]

            ACK = ACK_no_html / substring
            write(ACK, delay)
            increaseID(ipServer)

            # ACK from the client, GET response received by the client
            ACK = ipClient/TCP(sport=portSrc, dport=port, flags="A",
                               seq=ACK_no_html.ack, ack=ACK_no_html.seq +
                               len(substring))
            last_packet_client = ACK
            write(ACK, delay)
            increaseID(ipClient)

        # FIN, ACK from the client, the client ask to end connection
        FIN_ACK = ipClient/TCP(sport=portSrc, dport=port, flags="FA",
                               seq=ACK_no_html.ack, ack=ACK_no_html.seq
                               + len(html1[(nb_chunk-1)*max_data_length:nb_chunk*max_data_length]))
        write(FIN_ACK, delay)
        increaseID(ipClient)

    # FIN, ACK from the server, the server has received order to close connection
    FIN_ACK2 = ipServer/TCP(sport=port, dport=portSrc,
                            flags="FA", seq=FIN_ACK.ack, ack=FIN_ACK.seq+1)
    write(FIN_ACK2, delay)
    increaseID(ipServer)

    # ACK from the client, the client has received the FIN, ACK from the server
    ACK = ipClient/TCP(sport=portSrc, dport=port, flags="A",
                       seq=FIN_ACK2.ack, ack=FIN_ACK2.seq+1)
    write(ACK, delay)
    increaseID(ipClient)

    SeqNrClient = FIN_ACK2.seq
    SeqNrServer = ACK.seq

    LastIdServer = ipServer.fields.get('id')


def syn_flood(source, destination, port, ressource, delay=5):
    # initialize seq for the client
    SeqNrClient = int(RandNum(0, 2**32))

    ipClient = IP(dst=str(destination), src=str(source))
    ipServer = IP(dst=str(source), src=str(destination))

    ipClient.fields.update({'id': int(RandNum(0, 65535))})
    ipServer.fields.update({'id': LastIdServer})

    # Generate random source port number
    portSrc = int(RandNum(1024, 65535))

    # Create SYN packet and write it to PCAP
    SYN = ipClient/TCP(sport=portSrc, dport=port, flags="S", seq=SeqNrClient)
    write(SYN, delay)
    increaseID(ipClient)

    SeqNrClient = FIN_ACK2.seq
    SeqNrServer = ACK.seq

    LastIdServer = ipServer.fields.get('id')


ip1 = "192.168.0.1"
ip2 = "192.168.0.254"

if __name__ == '__main__':
    generateHTTPTraffic(source=ip1, destination=ip2,
                        port=80, ressource="toto.php")
