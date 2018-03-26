#! /bin/python3

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


def main():
    # use editcap -d tcpdump-blocked.pcap.1522057494 out_snort.pcap !!!!!!!!!!
    packets = associate_packet_class("traffic.pcap", "out_snort.pcap")


if __name__ == '__main__':
    main()
