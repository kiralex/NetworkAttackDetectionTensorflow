#!/bin/python3
import random
import datetime
from faker import Faker

import packet_utils as pu

fake = Faker()

pu.PCAP_FILE_NAME = "traffic.pcap"
NB_RESSOURCES = 10

DESTINATION_IP = "8.8.8.8"


def generate_normal_traffic(nbClients, nbTotalRequest, delayPackets=0.05,
                            delayRequests=2, start_timestamp=None):
    if start_timestamp is not None:
        pu.Timestamp = start_timestamp

    # generate client source IPs
    clients = [fake.ipv4() for _ in range(nbClients)]

    ressources = [fake.uri_path()
                  for _ in range(NB_RESSOURCES)]

    for _ in range(nbTotalRequest):
        client = random.choice(clients)
        ressource = random.choice(ressources)

        pu.http_request(client, DESTINATION_IP, 80, ressource, delayPackets)

        overlapping = True if random.randint(0, 1) > 0 else False
        if overlapping:
            pu.Timestamp -= random.randint(1, 10) * delayPackets
        else:
            pu.Timestamp += random.random() * delayRequests

def generate_simple_syn_flood(nbTotalRequest, delayPackets=0.05, start_timestamp=None):
    if start_timestamp is not None:
        pu.Timestamp = start_timestamp

    source = fake.ipv4()
    
    for _ in range(nbTotalRequest):
        pu.syn_attack(source, DESTINATION_IP, 80, delayPackets)

    


if __name__ == '__main__':
    generate_normal_traffic(10, 200)
    generate_simple_syn_flood(100, 0.05)
    pu.write_pcap()
