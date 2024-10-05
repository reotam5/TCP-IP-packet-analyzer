import sys
from scapy.all import argparse, sniff
from prettytable import PrettyTable
from scapy.interfaces import get_if_list
from tcp_ip_definition import definition


def capture_callback(hex):
    try:
        analyzed = definition.parse(hex)
        for x in analyzed:
            table = PrettyTable()
            table.align = "l"
            table.field_names = [
                "Field",
                "Formatted",
                "Hexadecimal",
                "Decimal",
                "Binary",
            ]

            for y in analyzed[x]:
                table.add_row(
                    [
                        y,
                        (
                            analyzed[x][y]["display_value"]
                            if analyzed[x][y]["display_value"] != None
                            else "--"
                        ),
                        (
                            ("0x" + analyzed[x][y]["hex"])
                            if analyzed[x][y]["hex"] != None
                            else "--"
                        ),
                        (
                            (analyzed[x][y]["decimal"])
                            if analyzed[x][y]["decimal"] != None
                            else "--"
                        ),
                        (
                            ("0b" + analyzed[x][y]["binary"])
                            if analyzed[x][y]["binary"] != None
                            else "--"
                        ),
                    ]
                )
            print(x + "\n" + str(table))
    except Exception as e:
        print(e)
        sys.exit("Something went wrong while analyzing packets")


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
        sys.exit("Failed to capture packets")


def parse_intereface_name(interface):
    if interface in get_if_list():
        return interface
    else:
        raise argparse.ArgumentTypeError(
            "{interface} is not a valid network interface name on your machine.".format(
                interface=interface
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This program captures a packet and display header details. It currently supports ARP, IPv4, TCP, and UDP packets."
    )
    parser.add_argument(
        "-i",
        required=True,
        help="Network interface name to capture packet on.",
        type=parse_intereface_name,
    )
    parser.add_argument(
        "-f",
        required=False,
        help="BPF filter that will be appied when capturing packet.",
    )
    args = parser.parse_args()

    capture(args.i, args.f, 1)
