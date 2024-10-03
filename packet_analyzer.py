from scapy.all import sniff
from packet_definition import definition
from prettytable import PrettyTable

def capture_callback(hex):
    print(hex)
    print('\n')
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
        print(x + '\n' + str(table) + '\n')


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


if __name__ == "__main__":
    capture("en0", 'tcp', 1)
