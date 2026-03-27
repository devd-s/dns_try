import socket
import struct

RESPONSE = 0x8000
NXDOMAIN = 0x8003

def dns_header(transaction_id: int, flags: int = RESPONSE, questions: int = 1, answers: int = 0, authority: int = 0, additional: int = 0) -> bytes:
    return struct.pack("!HHHHHH", transaction_id,flags,questions,answers,authority,additional)

def build_answer(domain_name: str, _type: int=1, _class: int=1, ttl:int = 60, ip_address: str="8.8.8.8") -> bytes:
#def build_answer(domain_name: bytes=b"\xc0\x0c", _type: int=1, _class: int=1, ttl:int = 60, ip_address: str="8.8.8.8") -> bytes:
    #name : 2 bytes
    name = encode_domain_name(domain_name)
    rdata = bytes(map(int, ip_address.split('.')))

    rlen=len(rdata)

    return (
        name +
        struct.pack("!H", _type) +
        struct.pack("!H", _class) +
        struct.pack("!I", ttl) +
        struct.pack("!H", rlen) +
        rdata
    )

def parse_domain_name(data: bytes, offset: int) -> tuple:
    """ Parses a domain name from the given data starting at the specified offset. Returns a tuple containing the domain name and the number of bytes read. """
    """dns header is of 12 bytes so the question section is from 13th byte"""
    """compression pointer is of 2 bytes and starts with 11 in the first two bits"""
    """# DNS Packet:
        data = b"\x00" * 12 + b"\x07example\x03com\x00" + b"\xc0\x0c"
#      └─ Header ─┘   └─ Domain (offset 12)─┘   └─ Pointer ─┘
#                                               Offset 25-26"""
    labels = []
    position = offset
    jumped = False
    jump_pos = 0

    while position < len(data):
        length = data[position]

        if (length & 0xC0) == 0xC0:
            if not jumped:
                jump_pos = position +2

            pointer = struct.unpack("!H", data[position:position+2])[0]

            pointer = pointer & 0x3FFF

            position = pointer
            jumped = True
            continue

        # domain end
        if length == 0:
            position += 1
            break

        position += 1
        label = data[position:position + length].decode("utf-8")
        labels.append(label)
        position += length

        domain_name = ".".join(labels)
    
    if jumped:
        bytes_read = jump_pos - offset
    else:
        bytes_read = position - offset

    return domain_name, bytes_read


def encode_domain_name(domain_name: str) -> bytes:

    encoded_domain = b""
    for label in domain_name.split('.'):
        encoded_domain += bytes([len(label)]) + label.encode("utf-8")
    encoded_domain += b"\x00"

    return encoded_domain

def parsing_question(data: bytes, offset: int) -> dict:
    domain_name, name_length = parse_domain_name(data, offset)
    position = offset + name_length

    # Extract the query type and class
    query_type = struct.unpack("!H", data[position:position+2])[0]
    query_class = struct.unpack("!H", data[position+2:position+4])[0]

    return {
        "domain_name": domain_name,
        "query_type": query_type,
        "query_class": query_class,
        "bytes_read": name_length + 4
    }

def build_question(domain_name: str, query_type: int=1, query_class: int = 1) -> bytes:
    qname = encode_domain_name(domain_name)
    return qname + (struct.pack("!HH", query_type, query_class))

def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Dns header is of 12 bytes
            # Transaction ID (high byte) : x04
            # Transaction ID low byte : xd2
            # flag (high byte) : x80
            # High Byte The most significant leftbyte (leftmost)
            # Low Byte The most significant byte (rightmost)
            tid = struct.unpack("!H", buf[0:2])[0]
            request_flags = struct.unpack("!H", buf[2:4])[0] # extract query flags
            question = buf[12:]
            qdcount = struct.unpack("!H", buf[4:6])[0] # extract number of questions


            # extracting rdbit from query flags
            rbbit_val= request_flags & 0x0100
            opcode_val = request_flags & 0x7800
            rcode_val = request_flags & 0x000F
            response_flag = RESPONSE | opcode_val |rbbit_val

            if opcode_val != 0:
                rcode_val = 0x0004
            else:
                rcode_val = 0x0000

            response_flag = RESPONSE | opcode_val |rbbit_val | rcode_val
            #response = b"\x04\xd2\x80" + (b"\x00" * 9)
            
            questions = []
            offset = 12 # question section starts from 13th byte and first 12 bytes are for header
            for i in range(qdcount):
                question = parsing_question(buf, offset)
                questions.append(question)
                print(f"    Q{i+1}: {question['domain_name']}")
                offset += question["bytes_read"]

            # building dns header
            header = dns_header(tid, flags=response_flag, questions=qdcount, answers=qdcount)

            question_section = b""
            for question in questions:
                question_section += build_question(question["domain_name"], question["query_type"], question["query_class"])

            answer_section = b""
            ip_addresses = ["8.8.8.8", "8.8.4.4"]

            for i, q in enumerate(questions):
                ip = ip_addresses[i % len(ip_addresses)]
                answer_section += build_answer(q["domain_name"], q["query_type"], q["query_class"],ip_address=ip)

                print(f"    A{i+1}: {q['domain_name']} → {ip}")
            

            #header = dns_header(tid,flags=response_flag, answers=1)
            #answer = build_answer(ip_address="8.8.8.8")
            #response = dns_header(tid) + question
            response = header + question_section + answer_section
            print (response)
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
