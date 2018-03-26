#!/bin/python3
import random
import sys
import argparse
import profile
from faker import Faker

import packet_utils as pu

fake = Faker()

pu.PCAP_FILE_NAME = "traffic.pcap"
NB_RESSOURCES = 10

DESTINATION_IP = "8.8.8.8"


def generate_normal_traffic(nbClients, nbTotalRequest, port, delayPackets=0.005,
                            delayRequests=3, start_timestamp=None):
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


def generate_simple_syn_flood(nbTotalRequest, port, delayPackets=0.005, start_timestamp=None):
    if start_timestamp is not None:
        pu.Timestamp = start_timestamp

    # pick a random source ip
    source = fake.ipv4()

    # make nbTotalRequest requests
    for _ in range(nbTotalRequest):
        pu.syn_packet(source, DESTINATION_IP, port, delayPackets)


def generate_distributed_syn_flood(nbClients, nbTotalRequest, port,
                                   delayPackets=0.005,
                                   start_timestamp=None):
    if start_timestamp is not None:
        pu.Timestamp = start_timestamp

    # generate requests
    for _ in range(nbTotalRequest):
        # pick a random client and ressource
        client = fake.ipv4()

        # make request
        pu.syn_packet(client, DESTINATION_IP, port, delayPackets)


def generate_traffic(filename, nbRequests, pSimpleSYN, pDistributedSYN, port, min_request, max_request=150):
    pu.PCAP_FILE_NAME = filename

    nbSimpleSYN = int(pSimpleSYN*nbRequests)
    nbDistributedSYN = int(pDistributedSYN*nbRequests)
    nbNormal = nbRequests - nbDistributedSYN - nbSimpleSYN

    MAX_CLIENTS = 30

    count = 0
    choices = []
    if nbNormal > 0:
        choices.append("normal")
    if nbSimpleSYN > 0:
        choices.append("simpleSYN")
    if nbDistributedSYN > 0:
        choices.append("distributedSYN")

    while count < nbRequests:
        choice = random.choice(choices)
        print(count)

        if choice == "normal":
            # if no other choice
            if len(choices) == 1:
                # general all remaining packets
                generate_normal_traffic(MAX_CLIENTS, nbNormal, port)
                count += nbNormal
                choices.remove("normal")
            else:
                maxi = random.randint(0, nbNormal)
                print(maxi)
                generate_normal_traffic(MAX_CLIENTS, maxi, port)
                nbNormal -= maxi
                count += maxi
                if nbNormal <= 0:
                    choices.remove("normal")

        if choice == "simpleSYN":
            # if no other choice
            if len(choices) == 1:
                # general all remaining packets
                generate_simple_syn_flood(nbSimpleSYN, port)
                count += nbSimpleSYN
                choices.remove("simpleSYN")
            else:
                maxi = random.randint(min_request, max_request)
                print(maxi)
                generate_simple_syn_flood(maxi, port)
                nbSimpleSYN -= maxi
                count += maxi
                if nbSimpleSYN <= 0:
                    choices.remove("simpleSYN")

        if choice == "distributedSYN":
            # if no other choice
            if len(choices) == 1:
                # general all remaining packets
                generate_distributed_syn_flood(
                    MAX_CLIENTS, nbDistributedSYN, port)
                count += nbDistributedSYN
                choices.remove("distributedSYN")
            else:
                maxi = random.randint(1, nbDistributedSYN)
                print(maxi)
                generate_distributed_syn_flood(
                    MAX_CLIENTS, maxi, port)
                nbDistributedSYN -= maxi
                count += maxi
                if nbDistributedSYN <= 0:
                    choices.remove("distributedSYN")


def main():
    parser = argparse.ArgumentParser(
        description=("Generate fake traffic and store it to PCAP file. "
                     + "The generated traffic can contain normal requests, single client "
                     + "SYN flood or distributed SYN flood"))
    parser.add_argument("filename", type=str,
                        help="output pcap containing generated traffic")

    parser.add_argument('--nbRequests', '-n', default=1000, type=int,
                        help='total number of requests to generate')
    parser.add_argument('--simpleSYN', "-s", default=1/3.0, type=float,
                        help='ratio of single client SYN flood attack',
                        metavar="[0-1]")
    parser.add_argument('--distributedSYN', '-ds', default=1/3.0, type=float,
                        help='ratio of distributed SYN flood attack',
                        metavar="[0-1]")

    args = parser.parse_args()

    if args.nbRequests < 0:
        sys.stderr.write("Error : NBREQUESTS must be greater than 0 !\n")
        sys.exit(1)

    if args.simpleSYN < 0 or args.simpleSYN > 1:
        sys.stderr.write("Error : SIMPLESYN must be in [0, 1]\n")
        sys.exit(1)

    if args.distributedSYN < 0 or args.distributedSYN > 1:
        sys.stderr.write("Error : DISTRIBUTEDSYN must be in [0, 1]\n")
        sys.exit(1)

    if args.simpleSYN + args.distributedSYN > 1:
        sys.stderr.write(
            "Error : SIMPLESYN + DISTRIBUTEDSYN must be smaller than 1\n")
        sys.exit(1)

    print("Summary of generation parametters:")
    print("\tNumber of requests: " + str(args.nbRequests))
    print("\tNormal traffic: " +
          str("%.2f" % ((1 -
                         args.simpleSYN - args.distributedSYN)*100)) + "%")
    print("\tSimple syn flood attacks: " +
          str("%.2f" % (args.simpleSYN*100)) + "%")
    print("\tDistributed syn flood attacks: " +
          str("%.2f" % (args.distributedSYN*100)) + "%")

    generate_traffic(args.filename, args.nbRequests,
                     args.simpleSYN, args.distributedSYN, 80, 100, 150)
    pu.reorder_pcap()


if __name__ == '__main__':
    main()
