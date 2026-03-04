import socket
import struct

RESPONSE = 0x8000
NXDOMAIN = 0x8003

def dns_header(transaction_id: int, flags: int = RESPONSE, questions: int = 1, answers: int = 0, authority: int = 0, additional: int = 0) -> bytes:
    return struct.pack("!HHHHHH", transaction_id,flags,questions,answers,authority,additional)


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
            question = buf[12:]

            #response = b"\x04\xd2\x80" + (b"\x00" * 9)
            response = dns_header(tid) + question
            print (response)
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
