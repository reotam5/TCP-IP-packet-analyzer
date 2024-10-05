from utils.definition import Definition, Field
from utils.helpers import *

definition = Definition(
    name="Ethernet Header",
    fields=[
        Field("Destination MAC", 6, display_mac_address),
        Field("Source MAC", 6, display_mac_address),
        Field("Ether Type", 2, display_ether_type),
    ],
    get_next_definition=lambda data: (
        ipv4
        if data["Ethernet Header"]["Ether Type"]["hex"] == "0800"
        else arp if data["Ethernet Header"]["Ether Type"]["hex"] == "0806" else None
    ),
)


ipv4 = Definition(
    name="IPv4",
    fields=[
        Field("Version", 0.5),
        Field("IHL", 0.5, lambda *args: "{value} double-words".format(value=get_decimal(*args))),
        Field("TOS", 1),
        Field("Total Length", 2,lambda *args: "{value} bytes".format(value=get_decimal(*args))),
        Field("IP identification", 2),
        Field("Flag: X (Reserved)", 1/8,lambda *args: "Reserved" if get_binary(*args) == "1" else "--"),
        Field("Flag: D (Do not Frag)", 1/8,lambda *args: "Do not Frag" if get_binary(*args) == "1" else "--"),
        Field("Flag: M (More Fragments)", 1/8,lambda *args: "More Fragments" if get_binary(*args) == "1" else "--"),
        Field("Offset", (5 / 8) + 1),
        Field("TTL", 1),
        Field("Protocol", 1, display_ip_protocol),
        Field("Checksum", 2),
        Field("Source Address", 4, display_ip),
        Field("Destination Address", 4, display_ip),
        Field("Options", lambda parsed, definition_start, field_start: (int(parsed["IPv4"]["IHL"]["decimal"]) * 4) - (field_start - definition_start)),
    ],
    get_next_definition=lambda data: (
        tcp
        if data["IPv4"]["Protocol"]["decimal"] == "6"
        else udp if data["IPv4"]["Protocol"]["decimal"] == "17" else None
    ),
)

tcp = Definition(
    name="TCP",
    fields=[
        Field("Source Port", 2, display_tcp_port),
        Field("Destination Port", 2, display_tcp_port),
        Field("Sequence Number", 4),
        Field("Acknowledgement Number", 4),
        Field("HL", 0.5, lambda *args: "{value} double-words".format(value=get_decimal(*args)),),
        Field("R", 0.5),
        Field("Flag: CWR", 1/8, lambda *args: "CWR" if get_binary(*args) == "1" else "--"),
        Field("Flag: ECE", 1/8, lambda *args: "ECE" if get_binary(*args) == "1" else "--"),
        Field("Flag: URG", 1/8, lambda *args: "URG" if get_binary(*args) == "1" else "--"),
        Field("Flag: ACK", 1/8, lambda *args: "ACK" if get_binary(*args) == "1" else "--"),
        Field("Flag: PUSH",1/8, lambda *args: "PUSH" if get_binary(*args) == "1" else "--"),
        Field("Flag: RES", 1/8, lambda *args: "RES" if get_binary(*args) == "1" else "--"),
        Field("Flag: SYN", 1/8, lambda *args: "SYN" if get_binary(*args) == "1" else "--"),
        Field("Flag: FIN", 1/8, lambda *args: "FIN" if get_binary(*args) == "1" else "--"),
        Field("Window Size", 2),
        Field("Checksum", 2),
        Field("Urgent Pointer", 2),
        Field("Options", lambda data, definition_start, field_start: ( int(data["TCP"]["HL"]["decimal"]) * 4) - (field_start - definition_start)),
    ],
)

udp = Definition(
    name="UDP",
    fields=[
        Field("Source Port", 2, display_udp_port),
        Field("Destination Port", 2, display_udp_port),
        Field("Length", 2, lambda *args: "{value} bytes".format(value=get_decimal(*args))),
        Field("Checksum", 2),
    ],
)

arp = Definition(
    name="ARP",
    fields=[
        Field("Hardware Address Type", 2),
        Field("Protocol Address Type", 2),
        Field("Hardware Address Length", 1),
        Field("Protocol Address Length", 1),
        Field("Opcode", 2, lambda *args: ( "Request" if get_decimal(*args) == "1" else "Response" if get_decimal(*args) == "2" else "--"),),
        Field("Source Hardware Address", lambda data, *_: int(data["ARP"]["Hardware Address Length"]["decimal"]), lambda *args: ( display_mac_address(*args) if args[0]["ARP"]["Hardware Address Type"]["decimal"] == "1" else "--"),),
        Field("Source Protocol Address", lambda data, *_: int(data["ARP"]["Protocol Address Length"]["decimal"]), lambda *args: ( display_ip(*args) if args[0]["ARP"]["Protocol Address Type"]["hex"] == "0800" else "--"),),
        Field("Target Hardware Address", lambda data, *_: int(data["ARP"]["Hardware Address Length"]["decimal"]), lambda *args: ( display_mac_address(*args) if args[0]["ARP"]["Hardware Address Type"]["decimal"] == "1" else "--"),),
        Field("Target Protocol Address", lambda data, *_: int(data["ARP"]["Protocol Address Length"]["decimal"]), lambda *args: ( display_ip(*args) if args[0]["ARP"]["Protocol Address Type"]["hex"] == "0800" else "--"),),
    ],
)
