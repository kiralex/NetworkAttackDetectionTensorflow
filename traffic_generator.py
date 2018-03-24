#!/bin/python3
import random
import datetime
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

    # generate list of possible request URI
    ressources = [fake.uri_path()
                  for _ in range(NB_RESSOURCES)]

    source = fake.ipv4()

    # generate requests
    for _ in range(nbTotalRequest):
        # pick a random client and ressource
        client = random.choice(clients)
        ressource = random.choice(ressources)

        # make request
        pu.syn_packet(client, DESTINATION_IP, port, delayPackets)


if __name__ == '__main__':
    # start normal traffic
    generate_normal_traffic(15, 300, 80)
    # generate_simple_syn_flood(150, 80)
    # generate_normal_traffic(10, 1050, 80)
    # generate_distributed_syn_flood(5, 750, 80)
    # generate_normal_traffic(10, 1050, 80)
    pu.write_pcap()
