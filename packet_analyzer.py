import sys
from scapy.all import argparse, sniff
from packet_definition import definition
from prettytable import PrettyTable

def capture_callback(hex):
    try:
        print('\ncaptured packet in hex:\n')
        print(hex)
        analyzed = definition.parse(hex)
        for x in analyzed:
            table = PrettyTable()
            table.align = 'l'
            table.field_names = ["Field", "Formatted", "Hexadecimal", "Decimal", "Binary"]
            
            for y in analyzed[x]:
                table.add_row([
                    y,
                    analyzed[x][y]['display_value'] if analyzed[x][y]['display_value'] != None else "--",
                    ('0x' + analyzed[x][y]['hex']) if analyzed[x][y]['hex'] != None else "--",
                    analyzed[x][y]['decimal'] if analyzed[x][y]['decimal'] != None else "--",
                    ('0b' + analyzed[x][y]['binary']) if analyzed[x][y]['binary'] != None else "--",
                ])
            print(x + '\n' + str(table))
    except Exception as e:
        print(e)
        sys.exit('Something went wrong while analyzing packets')


def capture(interface, filter, count):
    try:
        sniff(
            iface=interface,
            filter=filter,
            count=count,
            prn=lambda packet: capture_callback(bytes(packet).hex()),
        )
    except Exception as e:
        print(e)
        sys.exit('Failed to capture packets')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This program captures packets and display details of the packets. It supports APR, IPv4, TCP, and UDP headers.")
    parser.add_argument(
        "--interface",
        required=True,
        help="The network interface name to capture packet on."
    )
    parser.add_argument(
        "--filter",
        required=False,
        help="BPF to filter packets based on your interests."
    )
    args = parser.parse_args()

    capture(args.interface, args.filter, 5)
