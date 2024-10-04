def get_hex(data, definition_name, field_name):
    return data[definition_name][field_name]["hex"]


def get_decimal(data, definition_name, field_name):
    return data[definition_name][field_name]["decimal"]


def get_binary(data, definition_name, field_name):
    return data[definition_name][field_name]["binary"]


def display_mac_address(*args):
    hex = get_hex(*args)
    return ":".join(hex[i : i + 2] for i in range(0, len(hex), 2))


def display_double_words(*args):
    decimal = get_decimal(*args)
    return "{value} double-words".format(value=decimal)


def display_ip(*args):
    hex = get_hex(*args)
    return ".".join(str(int(hex[i : i + 2], 16)) for i in range(0, len(hex), 2))

def display_ether_type(*args):
    hex = get_hex(*args)
    table = {
        "0800": "IPv4",
        "0806": "ARP",
        "86dd": "IPv6",
    }
    return table[hex] if hex in table else "--"

def display_ipv4_protocol(*args):
    decimal = get_decimal(*args)
    table = {
        "1": "ICMP",
        "2": "IGMP",
        "6": "TCP",
        "17": "UDP",
        "41": "IPv6",
        "47": "GRE",
        "50": "ESP",
        "51": "AH",
        "115": "L2TP",
    }
    return table[decimal] if decimal in table else "--"


def display_tcp_port(*args):
    decimal = get_decimal(*args)
    table = {
        "20": "ftp-data",
        "21": "ftp",
        "22": "ssh",
        "23": "telnet",
        "25": "smtp",
        "43": "whois",
        "53": "dns",
        "80": "http",
        "88": "kerberos",
        "110": "pop3",
        "113": "authd",
        "119": "nntp",
        "143": "imap",
        "179": "bgp",
        "443": "https",
        "445": "MS SMB",
        "465": "SMTPS",
        "1433": "MS MQL",
        "3128": "Squid",
        "3306": "Mysql",
        "3389": "MS Term.",
    }
    return table[decimal] if decimal in table else "--"


def display_udp_port(*args):
    decimal = get_decimal(*args)
    table = {
        "7": "echo",
        "19": "chargen",
        "53": "domain",
        "67": "DHCPs",
        "68": "DHCPc",
        "69": "tftp",
        "123": "ntp",
        "137": "netbios-ns",
        "138": "netbios",
        "161": "snmp",
        "162": "snmp-trap",
        "500": "isakmp",
        "514": "syslog",
        "520": "Rip",
        "546": "DHCPv6c",
        "547": "DHCPv6c",
        "1900": "SSDP",
        "5353": "mDNS",
    }
    return table[decimal] if decimal in table else "--"

