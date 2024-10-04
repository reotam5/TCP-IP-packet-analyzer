from typing import Any, Callable
import math


class Field:
    def __init__(self, name, length, parser: None | Callable[[Any, str, str], str] = None):
        self.name = name
        self.length: int | Callable[[Any, float, float], float] = length
        self.parser = parser


class Definition:
    def __init__(self, name, fields, get_next_definition=None):
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
                # if -1 is reserved to represent all remaining data
                if field.length == -1:
                    byte_field_length = ((len(data) * 4) - bit_pointer) / 8 
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
            result[self.name][field.name]["hex"] = hex if can_represent_in_hex else None
            result[self.name][field.name]["binary"] = binary if not can_represent_in_hex else None
            result[self.name][field.name]["decimal"] = decimal
            result[self.name][field.name]["display_value"] = field.parser(result, self.name, field.name) if callable(field.parser) else None

            # increment bit pointer
            bit_pointer += byte_field_length * 8

        # if there is next definition to lookup, recursively call parse and update the result
        if self.get_next_definition:
            if next_definition := self.get_next_definition(result):
                result.update(next_definition.parse(data, bit_pointer))

        return result
