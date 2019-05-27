
"""
This file contains functions that help the controller in IPv6 string manipulation.

List of functions contained:

+=================================================================+
|      Function Name        |                Usage                |
+=================================================================+
|decompress_ipv6            |Get full ipv6 representation         |
|concat_with_delimiter      |Merge elements of a list (strings)   |
|generate_random_mac        |Generate a random MAC address        |
|generate_llu_ipv6          |Generate a Link Local Unicast address|
|extract_mac_from_ipv6      |Get the MAC address of an ipv6 node  |
+=================================================================+
"""


# def set_prefix(prefix: str):
#
#     ipv6_routing_prefixes = {
#         "global unicast": "2000",
#         "link-local unicast": "fe80",
#         "unique-local address": "fc00",
#         "multicast": "ff00"
#     }
#
#     if prefix in ipv6_routing_prefixes.keys():
#         return ipv6_routing_prefixes[prefix]
#     else:
#         return None


def decompress_ipv6(ipv6: str) -> list:
    """
    Take a string representation of an IPv6 address (e.g: fe80::200:ff:fe00:3) and
    decompress it, based on the compressing convention for IPv6 addresses (specified in 'RFC 5952').

    :param ipv6: The IPv6 represented as a string (type: str)
    :return: The full, decompressed IPv6 string representation as a list. Each element is a 16-bit hex number.
    """
    ipv6_blocks = ipv6.split(":")
    block_size = 4
    ipv6_blocks_count = 8

    for i in range(ipv6_blocks_count):
        block_bits = len(ipv6_blocks[i])

        # If block was abbreviated (leading 0 was trimmed), then add back the 0(s)
        if block_size > block_bits > 0:
            missing_zeros = block_size - block_bits
            ipv6_blocks[i] = (str(0)*missing_zeros) + ipv6_blocks[i]

        # If the block has consecutive blocks of 0's abbreviated, then add them back
        elif block_bits is 0:
            ipv6_blocks[i] = '0000'
            while len(ipv6_blocks) < ipv6_blocks_count:
                ipv6_blocks.insert(i, '0000')

    return ipv6_blocks


def concat_with_delimiter(list_to_concat: list, delimiter=":") -> str:
    """
    This method takes a list of strings and concatenates its elements, by placing a delimiter between them.
    :param list_to_concat: The list to concatenate the elements of.
    :param delimiter: The delimiter that will be placed between each of the list's elements (default is ":").
    :return: The concatenated string
    """
    return delimiter.join(list_to_concat)


def generate_random_mac(delimiter=":") -> str:
    """
    This method will generate a random MAC address
    :param delimiter: How the mac address will be split. I.e. delimiter='-' will produce xx-xx-xx-xx-xx-xx, etc..
    :return: A string representation of a MAC address
    """
    from random import randint

    legal_chars = "0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f".split(',')
    length_in_bytepairs = 6  # a MAC address has 12 bytes and is written in pairs. i.e. xx:xx:xx:xx:xx:xx(6 pairs total)
    mac_address = []

    for pair in range(length_in_bytepairs):
        index1 = randint(0, len(legal_chars)-1)
        index2 = randint(0, len(legal_chars)-1)
        byte_pair = legal_chars[index1]+legal_chars[index2]
        mac_address.append(byte_pair)

    mac_address[0] = mac_address[0][0]+"0"

    return concat_with_delimiter(mac_address, delimiter)


def generate_llu_ipv6(mac_address: str) -> str:
    delimiter = mac_address[2]  # If mac address has correct format (6 byte pairs), then 3rd element is delimiter
    mac_bytes = mac_address.split(delimiter)
    llu_ipv6 = ['fe80', '']

    byte1 = mac_bytes.pop(0)
    # Reverse the complemented first byte
    original_byte = (int(byte1, 16))  # convert to integer, base 16
    complemented_byte = original_byte ^ (1 << 1)  # flip the second low-order bit only

    byte1 = hex(complemented_byte)[2:]
    byte2 = mac_bytes.pop(0)
    byte3 = mac_bytes.pop(0)
    byte4 = "ff"
    byte5 = "fe"
    byte6 = mac_bytes.pop(0)
    byte7 = mac_bytes.pop(0)
    byte8 = mac_bytes.pop(0)

    llu_ipv6.append(byte1+byte2)
    llu_ipv6.append(byte3+byte4)
    llu_ipv6.append(byte5+byte6)
    llu_ipv6.append(byte7+byte8)

    for i in range(len(llu_ipv6)):
        while llu_ipv6[i].startswith("0"):
            llu_ipv6[i] = llu_ipv6[i][1:]

    return concat_with_delimiter(llu_ipv6, ":")


def extract_mac_from_ipv6(ipv6):
    """
    This function will extract a node's MAC address, given a legal Link-Local IPv6 address of that node.
    :param ipv6: Can be either a String representation of an IPv6 (compressed or decompressed) or a list,
    where each element is a 16-bit (represented with hexadecimal notation, type: str) block of the IPv6 address.
    Examples of acceptable list elements: '0000', '2a3e', 'ffff', etc..
    If arg is not of type str or list, and if not all list elements are of accepted length, then an exception
    will be raised, specifying the problem.
    :return: A string representation of the extracted MAC address, as represented within the RYU framework
    """
    if isinstance(ipv6, str):
        ipv6_blocks = decompress_ipv6(ipv6)
    elif isinstance(ipv6, list):
        for i in range(len(ipv6)):
            length = len(ipv6[i])
            if length is not 4:
                raise ValueError("Every element in list should have a length of '4'."
                                 " '{0}' at position {1} has a length of '{2}'."
                                 .format(ipv6[i], i+1, length))
        ipv6_blocks = ipv6
    else:
        raise TypeError("Expected types: str, list. Found {argtype} instead.".format(argtype=type(ipv6)))

    # Discard the 64-bit prefix and get the 64-bit Interface Identifier
    temp = ipv6_blocks[4:]
    mac_address = []
    # Get all the 16-bit blocks (2 bytes) and convert them to 8-bit blocks (1 byte)
    for block in temp:
        mac_address.append(block[:2])
        mac_address.append(block[2:])

    # Remove the inserted bytes 0xff and 0xfe from the 3rd and 4th bytes of the MAC address (LLA specification)
    del mac_address[3:5]

    # Reverse the complemented first byte
    complemented_byte = (int(mac_address[0], 16))  # convert to integer, base 16
    original_byte = complemented_byte ^ (1 << 1)   # flip the second low-order bit only

    # Replace first byte, with original MAC address byte
    mac_address[0] = hex(original_byte)[2:]
    while len(mac_address[0]) < 2:
        mac_address[0] = "0"+mac_address[0]  # add any missing zeros, to get the complete MAC address

    return concat_with_delimiter(mac_address)
