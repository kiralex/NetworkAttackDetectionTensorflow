#! /bin/python3

import csv
from scapy.all import *


def associate_packet_class(traffic_filename, snort_output_filename):
    packets = rdpcap(traffic_filename)
    attacks = rdpcap(snort_output_filename)

    for p in packets:
        p.attack = False

    i = 0
    nb_trouve = 0
    for pa in attacks:
        found = None
        while found is None and i < len(packets):
            p = packets[i]
            if (p.time == pa.time
                and p.src == pa.src
                    and p.fields.get('id') == pa.fields.get('id')):
                found = p

            i += 1

        if found is not None:
            found.attack = True
            nb_trouve += 1

    return packets


def save_csv(packets, filename="out.csv"):
    file = open(filename, "w")
    try:
        writer = csv.writer(file)

        writer.writerow(("timestamp", "source_ip", "destination_ip", "source_port",
                         "destination_port", "flags", "identification", "data", "class"))

        for p in packets:
            writer.writerow(
                (
                    p.time,
                    p.src,
                    p.dst,
                    p[TCP].sport,
                    p[TCP].dport,
                    # str(p[TCP].flags),
                    p.sprintf('%TCP.flags%'),
                    p.id,
                    p["Raw"].load.decode('ascii') if p.haslayer("Raw") else "",
                    "attack" if p.attack else "safe-packet"
                )
            )

    finally:
        file.close()


def main():
    # use editcap -d tcpdump-blocked.pcap.1522057494 out_snort.pcap !!!!!!!!!!
    packets = associate_packet_class("bigger_gen.pcap", "out_snort_100000.pcap")
    save_csv(packets, "out_100000.csv")


if __name__ == '__main__':
    main()
