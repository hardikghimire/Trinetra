import socket
import struct

def get_version():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        sock.connect(("148.113.9.237", 1883))
        
        # Proper CONNECT packet
        client_id = b"test123"
        connect = bytearray()
        connect.append(0x10)  # CONNECT
        connect.append(12 + len(client_id))  # Remaining length
        connect.extend(b"\x00\x04MQTT\x04\x02\x00\x3c")  # Protocol, flags, keepalive
        connect.extend(struct.pack(">H", len(client_id)))
        connect.extend(client_id)
        
        sock.send(connect)
        
        # Read CONNACK
        connack = sock.recv(4)
        if connack[3] != 0:
            print(f"Auth required (code: {connack[3]})")
            sock.close()
            return
        
        # Subscribe to version topic
        topic = b"$SYS/broker/version"
        subscribe = bytearray()
        subscribe.append(0x82)  # SUBSCRIBE with QoS1
        subscribe.append(2 + 2 + len(topic) + 1)  # Remaining length
        subscribe.extend(b"\x00\x01")  # Packet ID
        subscribe.extend(struct.pack(">H", len(topic)))
        subscribe.extend(topic)
        subscribe.append(0x00)  # QoS 0
        
        sock.send(subscribe)
        
        # Read SUBACK
        suback = sock.recv(5)
        
        # Read PUBLISH (version message)
        while True:
            try:
                data = sock.recv(256)
                if data:
                    # Extract version string from packet
                    # Skip header bytes to find the actual version
                    for i in range(len(data)):
                        if 32 <= data[i] <= 126:  # ASCII printable
                            version = data[i:].split(b'\x00')[0].decode()
                            if 'mosquitto' in version or 'version' in version:
                                print(f"Broker version: {version}")
                                break
                    break
            except:
                break
                
    except Exception as e:
        print(f"Cannot get version: {e}")
    finally:
        sock.close()

get_version()
