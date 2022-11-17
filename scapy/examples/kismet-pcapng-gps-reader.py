#!/usr/bin/env python3

import argparse
import os
import sys
import binascii

from scapy.all import *
from scapy.all import Raw
from scapy.utils import RawPcapNgReader

from scapy.consts import OPT_CUSTOM_BYTES_SAFE

KISMET_PEN = 55922
KISMET_GPS_MAGIC = 0x47

'''
A very simplistic example of using this modified scapy to extract the GPS
information embedded in a Kismet PCAPNG stream.  
'''

def extract_kismet_gps(custom):

    def fixed6_4_to_float(fixed):
        if (fixed > 3600000000):
            print('{} is an invalid value for fixed6_4_to_float'.format(fixed))
            return None

        remapped = fixed - (180000 * 10000)
        return remapped / 10000.0

    def fixed3_7_to_float(fixed):
        if (fixed > 3600000000):
            print('{} is an invalid value for fixed3_7_to_float'.format(fixed))
            return None

        remapped = fixed - (180.0 * 10000000.0)
        return remapped / 10000000.0

    for custom_field in custom:
        if int(custom_field['code']) == OPT_CUSTOM_BYTES_SAFE:
            payload = custom_field['payload']

        if type(payload) is bytes:

            kismet_pen = struct.unpack('<L', payload[:4])[0]
            kismet_gps_magic = struct.unpack('<B', payload[4:5])[0]
            kismet_gps_version = struct.unpack('<B', payload[5:6])[0]

            if kismet_pen == KISMET_PEN and kismet_gps_magic == KISMET_GPS_MAGIC and kismet_gps_version == 0x1:
                kismet_gps_len, kismet_gps_bitmask = struct.unpack('<HL', payload[6:12])
                kismet_gps_values = struct.unpack('<LLL', payload[12:])
                longitude = fixed3_7_to_float(kismet_gps_values[0])
                latitude = fixed3_7_to_float(kismet_gps_values[1])
                altitude = fixed6_4_to_float(kismet_gps_values[2])
                return (latitude, longitude, altitude)
            else:
                print('payload pen is not kismet ', payload_pen)
                return None


def get_packet_gps(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        if layer.custom:
            latitude, longitude, altitude = extract_kismet_gps(layer.custom)
            print("get_packet_gps: lat ", latitude, "lon : ", longitude, "alt : ", altitude)

        counter += 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)

    args = parser.parse_args()
    file_name = args.pcap

    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    print('Opened {}'.format(file_name), file=sys.stderr)
    sniff(offline=file_name, monitor=True, prn=get_packet_gps, store=0)

    sys.exit(0)
