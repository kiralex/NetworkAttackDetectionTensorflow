#!/bin/python3
import random
import sys
import argparse
from faker import Faker

import packet_utils as pu

fake = Faker()

pu.PCAP_FILE_NAME = "traffic.pcap"
NB_RESSOURCES = 10

DESTINATION_IP = "8.8.8.8"


def generate_normal_traffic(nbClients, nbTotalRequest, port, delayPackets=0.05,
                            delayRequests=2, start_timestamp=None):
    if start_timestamp is not None:
        pu.Timestamp = start_timestamp

    # generate client source IPs
    clients = [fake.ipv4() for _ in range(nbClients)]

    # generate list of possible request URI
    ressources = [fake.uri_path()
                  for _ in range(NB_RESSOURCES)]

    # generate requests
    for _ in range(nbTotalRequest):
        # pick a random client and ressource
        client = random.choice(clients)
        ressource = random.choice(ressources)

        # make request
        pu.http_request(client, DESTINATION_IP, port, ressource, delayPackets)

        # 50% of overlapping between clients
        # if overlapping : remove 1 <= n <= 10 delayPackets to timestamp, to well, overlap
        # if not : wait between 0 <= n <= delayPackets
        overlapping = True if random.randint(0, 1) > 0 else False
        if overlapping:
            pu.Timestamp -= random.randint(1, 10) * delayPackets
        else:
            pu.Timestamp += random.random() * delayRequests


def generate_simple_syn_flood(nbTotalRequest, port, delayPackets=0.05, start_timestamp=None):
    if start_timestamp is not None:
        pu.Timestamp = start_timestamp

    # pick a random source ip
    source = fake.ipv4()

    # make nbTotalRequest requests
    for _ in range(nbTotalRequest):
        pu.syn_packet(source, DESTINATION_IP, port, delayPackets)


def generate_distributed_syn_flood(nbClients, nbTotalRequest, port,
                                   delayPackets=0.05,
                                   start_timestamp=None):
    if start_timestamp is not None:
        pu.Timestamp = start_timestamp

    # generate client source IPs
    clients = [fake.ipv4() for _ in range(nbClients)]

    # generate requests
    for _ in range(nbTotalRequest):
        # pick a random client and ressource
        client = random.choice(clients)

        # make request
        pu.syn_packet(client, DESTINATION_IP, port, delayPackets)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Generate fake traffic and store it to PCAP file. "
        + "The generated traffic can contain normal requests, single client "
        + "SYN flood or distributed SYN flood")
    parser.add_argument("filename", type=str,
                        help="output pcap containing generated traffic")

    parser.add_argument('--nbRequests', '-n', default=1000, type=int,
                        help='total number of requests to generate')
    parser.add_argument('--simpleSYN', "-s", default=1/3.0, type=float,
                        help='ratio of single client SYN flood attack',
                        metavar="[0-1]")
    parser.add_argument('--distributedSyn', '-ds', default=1/3.0, type=float,
                        help='ratio of distributed SYN flood attack',
                        metavar="[0-1]")

    args = parser.parse_args()

    if args.nbRequests < 0:
        sys.stderr.write("Error : NBREQUESTS must be greater than 0 !\n")
        sys.exit(1)

    if args.simpleSYN < 0 or args.simpleSYN > 1:
        sys.stderr.write("Error : SIMPLESYN must be in [0, 1]\n")
        sys.exit(1)

    if args.distributedSyn < 0 or args.distributedSyn > 1:
        sys.stderr.write("Error : DISTRIBUTEDSYN must be in [0, 1]\n")
        sys.exit(1)

    if args.simpleSYN + args.distributedSyn > 1:
        sys.stderr.write(
            "Error : SIMPLESYN + DISTRIBUTEDSYN must be smaller than 1\n")
        sys.exit(1)

    print("Summary of generation parametters:")
    print("\tNumber of requests: " + str(args.nbRequests))
    print("\tNormal traffic: " + str("%.2f" % ((1 -
                                     args.simpleSYN - args.distributedSyn)*100))
          + "%")
    print("\tSimple syn flood attacks: " + str("%.2f" % (args.simpleSYN*100)) + "%")
    print("\tDistributed syn flood attacks: " +
          str("%.2f" % (args.distributedSyn*100)) + "%")

    # start normal traffic
    generate_normal_traffic(15, 300, 80)
    # generate_simple_syn_flood(150, 80)
    # generate_normal_traffic(10, 1050, 80)
    # generate_distributed_syn_flood(5, 750, 80)
    # generate_normal_traffic(10, 1050, 80)
    pu.write_pcap()
