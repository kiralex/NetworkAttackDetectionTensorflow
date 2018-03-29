#! /bin/python3

import csv
import argparse
from scapy.all import *


def associate_packet_class(traffic_filename, snort_output_filename):
    packets = rdpcap(traffic_filename)
    attacks = rdpcap(snort_output_filename)

    for p in packets:
        p.attack = False

    i = 0
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

    return packets


def save_csv(packets, filename="out.csv"):
    # open file
    file = open(filename, "w")

    try:
        # initialize CSV writer for the file
        writer = csv.writer(file)

        # writing header file
        writer.writerow(("timestamp", "source_ip", "destination_ip", "source_port",
                         "destination_port", "flags", "identification", "data", "class"))

        # for each packet
        for p in packets:
            # write values of the packet
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
    except err:
        print("Error : %s" % e)

    finally:
        # closing file
        file.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=str, required=True,
                        help="source pcap file")
    
    parser.add_argument("--snort-out", type=str, required=True,
                        help="snort output pcap file")

    
    parser.add_argument("--csv-out", type=str, required=True,
                        help="output csv file")
    args = parser.parse_args()

    # use editcap -d tcpdump-blocked.pcap.1522057494 out_snort.pcap !!!!!!!!!!
    packets = associate_packet_class(
        args.source, args.snort_out)
    save_csv(packets, args.csv_out)


if __name__ == '__main__':
    main()
