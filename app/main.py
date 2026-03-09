import socket
import struct

RESPONSE = 0x8000
NXDOMAIN = 0x8003

def dns_header(transaction_id: int, flags: int = RESPONSE, questions: int = 1, answers: int = 0, authority: int = 0, additional: int = 0) -> bytes:
    return struct.pack("!HHHHHH", transaction_id,flags,questions,answers,authority,additional)

def build_answer(name: bytes=b"\xc0\x0c", _type: int=1, _class: int=1, ttl:int = 60, ip_address: str="8.8.8.8") -> bytes:
    #name : 2 bytes

    rdata = bytes(map(int, ip_address.split('.')))

    rlen=len(rdata)

    return (
        name +
        struct.pack("!H", _type) +
        struct.pack("!H", _class) +
        struct.pack("!H", ttl) +
        struct.pack("!H", rlen) +
        rdata
    )




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
            #tid = struct.unpack("!H", buf[0:2])[0]
            question = buf[12:]

            #response = b"\x04\xd2\x80" + (b"\x00" * 9)
            header = dns_header(transaction_id=1234, answers=1)
            answer = build_answer(ip_address="8.8.8.8")
            #response = dns_header(tid) + question
            response = header + question + response
            print (response)
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
