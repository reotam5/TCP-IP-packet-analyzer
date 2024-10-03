from typing import Any, Callable
import math


class Field:
    def __init__(self, name, length, parser: None | Callable[[Any, str, str], str] = None):
        self.name = name
        self.length: int | Callable[[Any, float, float], float] = length
        self.parser = parser


class Definition:
    def __init__(self, name, fields, get_next_definition = None):
        self.name = name
        self.fields: list[Field] = fields
        self.get_next_definition = get_next_definition

    def parse(self, data, start=0):
        result = {}
        bit_pointer = start
        for field in self.fields:

            # Field length is either calculated in callback, or just a passed integer
            # Represented in bytes
            if callable(field.length):
                byte_field_length = field.length(result, start / 8, bit_pointer / 8)
            else:
                byte_field_length = field.length

            if byte_field_length == 0:
                continue
            
            # Current bit_pointer has to be pointing to the begining of a hex digit
            # also, 4 bits is one hex digit, so when representing in hex, data must be divisible by 4 bits. otherwise, resulting hex will have digits that don't appear in actual packet hex
            is_divisible_by_4_bits = (byte_field_length * 8) % 4 == 0
            is_pointing_to_start_of_hex = bit_pointer % 4 == 0
            can_represent_in_hex = is_divisible_by_4_bits and is_pointing_to_start_of_hex 

            # extracting hex character(s) which represents the current field
            # starting index is bit pointer devided by 4 (floored with integer division). We take floor because bit pointer could be pointing to a bit that is in the middle of hex representation, in which case, we want to include that hex 
            # ending index is start plus length of the bytes * 2 (ceiled). Multipling bytes by 2 gives us the length of hex representation. We take ceil to include the bits in the middle of hex representation. 
            hex_start = int(bit_pointer // 4)
            hex_end = hex_start + math.ceil(byte_field_length * 2)
            hex = data[hex_start:hex_end]

            # converting hex to dase 10. Keep in mind that this could include extra bits if length of the field is not divisible by 4 bit
            full_decimal = str(int(hex, 16))
           
            # bin function returns a binary representation of an integer like '0b10'. We don't need the prefix '0b', so remove it with [2:]. lastly, we pad with leading 0s to match the length with hex digit * 4. For example, 0x1 would give us 0001 instead of just 1.
            # starting index is mod 4. This represents how many bits were off from hex-representable digit.
            # ending index is start plus field length in bit.
            binary_from_hex = bin(int(full_decimal))[2:].zfill(len(hex) * 4)
            binary_start = int(bit_pointer % 4)
            binary_end = binary_start + int(byte_field_length * 8)
            binary = binary_from_hex[binary_start:binary_end]

            # converting binary to base 10. Unlike full_decimal, this is correct representation in base 10 even if the field length is not divisible by 4 bit
            decimal = str(int(binary, 2))

            # just setting up dictionary to store all what we computed above...
            if self.name not in result:
                result[self.name] = {}
            result[self.name][field.name] = {}

            # storing computed hex, decimal, and binary values into dictionary
            # binary is only stored if the value could not be represented in hex. This prevents a long binary.
            result[self.name][field.name]['hex'] = hex if can_represent_in_hex else None
            result[self.name][field.name]['binary'] = binary if (not can_represent_in_hex) else None
            result[self.name][field.name]['decimal'] = decimal
            result[self.name][field.name]['display_value'] = field.parser(result, self.name, field.name) if callable(field.parser) else None

            # increment bit pointer
            bit_pointer += byte_field_length * 8

        # if there is next definition to lookup, recursively call parse and update the result
        if self.get_next_definition:
            if next_definition := self.get_next_definition(result):
                result.update(next_definition.parse(data, bit_pointer))

        return result


def get_hex(data, definition_name, field_name):
    return data[definition_name][field_name]['hex']

def get_decimal(data, definition_name, field_name):
    return data[definition_name][field_name]['decimal']

def get_binary(data, definition_name, field_name):
    return data[definition_name][field_name]['binary']

def display_mac_address(*args):
    hex = get_hex(*args)
    return ":".join(hex[i : i + 2] for i in range(0, len(hex), 2))

def display_double_words(*args):
    decimal = get_decimal(*args)
    return "{value} double-words".format(value=decimal)

def display_ip(*args):
    hex = get_hex(*args)
    return ".".join(str(int(hex[i : i + 2], 16)) for i in range(0, len(hex), 2))

def display_ipv4_protocol(*args):
    decimal = get_decimal(*args)
    table = {
        '1': "ICMP",
        '2': "IGMP",
        '6': "TCP",
        '17': "UDP",
        '41': "IPv6",
        '47': "GRE",
        '50': "ESP",
        '51': "AH",
        '115': "L2TP",
    }
    return table[decimal] if decimal in table else "--"

def display_tcp_port(*args):
    decimal = get_decimal(*args)
    table = {
        '20': "ftp-data",
        '21': "ftp",
        '22': "ssh",
        '23': "telnet",
        '25': "smtp",
        '43': "whois",
        '53': "dns",
        '80': "http",
        '88': "kerberos",
        '110': "pop3",
        '113': "authd",
        '119': "nntp",
        '143': "imap",
        '179': "bgp",
        '443': "https",
        '445': "MS SMB",
        '465': "SMTPS",
        '1433': "MS MQL",
        '3128': "Squid",
        '3306': "Mysql",
        '3389': "MS Term.",
    }
    return table[decimal] if decimal in table else "--"

def display_tcp_flags(*args):
    hex = get_hex(*args)
    binary_representation = bin(int(hex, 16))[2:].zfill(int(len(hex) * 4))
    flags = ["CWR", "ECE", "URG", "ACK", "PUSH", "RES", "SYN", "FIN"]
    enabled = []
    for x in range(len(binary_representation)):
        if binary_representation[x] == "1":
            enabled.append(flags[x])

    if len(enabled) > 0:
        return ", ".join(enabled)
    return "--"


def display_udp_port(*args):
    decimal = get_decimal(*args)
    table = {
        '7': "echo",
        '19': "chargen",
        '53': "domain",
        '67': "DHCPs",
        '68': "DHCPc",
        '69': "tftp",
        '123': "ntp",
        '137': "netbios-ns",
        '138': "netbios",
        '161': "snmp",
        '162': "snmp-trap",
        '500': "isakmp",
        '514': "syslog",
        '520': "Rip",
        '546': "DHCPv6c",
        '547': "DHCPv6c",
        '1900': "SSDP",
        '5353': "mDNS",
    }
    return table[decimal] if decimal in table else "--"


definition = Definition(
    name="Ethernet Header",
    fields=[
        Field("Destination MAC", 6, display_mac_address),
        Field("Source MAC", 6, display_mac_address),
        Field("Ether Type", 2),
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
        Field("Total Length", 2, lambda *args: "{value} bytes".format(value=get_decimal(*args))),
        Field("IP identification", 2),
        Field("Flag: X (Reserved)", 1 / 8, lambda *args: "Reserved" if get_binary(*args) == "1" else "--"),
        Field("Flag: D (Do not Frag)",1 / 8,lambda *args: "Do not Frag" if get_binary(*args) == "1" else "--",),
        Field("Flag: M (More Fragments)",1 / 8,lambda *args: "More Fragments" if get_binary(*args) == "1" else "--",),
        Field("Offset", (5 / 8) + 1),
        Field("TTL", 1),
        Field("Protocol", 1, display_ipv4_protocol),
        Field("Checksum", 2),
        Field("Source Address", 4, display_ip),
        Field("Destination Address", 4, display_ip),
        Field("Options", lambda parsed, definition_start, field_start: (int(parsed['IPv4']['IHL']['decimal']) * 4) - (field_start - definition_start)),
    ],
    get_next_definition=lambda data: tcp if data["IPv4"]["Protocol"]["decimal"] == "6" else udp if data["IPv4"]["Protocol"]["decimal"] == "17" else None,
)

tcp = Definition(
    name="TCP",
    fields=[
        Field("Source Port", 2, display_tcp_port),
        Field("Destination Port", 2, display_tcp_port),
        Field("Sequence Number", 4),
        Field("Acknowledgement Number", 4),
        Field("HL", 0.5, lambda *args: "{value} double-words".format(value=get_decimal(*args))),
        Field("R", 0.5),
        Field("Flags", 1, display_tcp_flags),
        Field("Window Size", 2),
        Field("Checksum", 2),
        Field("Urgent Pointer", 2),
        Field("Options", lambda data, definition_start, field_start: (int(data["TCP"]["HL"]["decimal"]) * 4) - (field_start - definition_start)),
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
        Field("Opcode", 2, lambda *args: ("Request" if get_decimal(*args) == "1" else "Response" if get_decimal(*args) == "2" else "--")),
        Field("Source Hardware Address", lambda data, *_: int(data["ARP"]["Hardware Address Length"]["decimal"]), lambda *args: display_mac_address(*args) if args[0]["ARP"]["Hardware Address Type"]["decimal"] == "1" else "--"),
        Field("Source Protocol Address", lambda data, *_: int(data["ARP"]["Protocol Address Length"]["decimal"]), lambda *args: display_ip(*args) if args[0]["ARP"]["Protocol Address Type"]["hex"] == "0800" else "--"),
        Field("Target Hardware Address", lambda data, *_: int(data["ARP"]["Hardware Address Length"]["decimal"]), lambda *args: display_mac_address(*args) if args[0]["ARP"]["Hardware Address Type"]["decimal"] == "1" else "--"),
        Field("Target Protocol Address", lambda data, *_: int(data["ARP"]["Protocol Address Length"]["decimal"]), lambda *args: display_ip(*args) if args[0]["ARP"]["Protocol Address Type"]["hex"] == "0800" else "--"),
    ],
)
