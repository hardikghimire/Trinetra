import socket
import struct
import json
import time
from typing import Dict, List, Tuple

def get_all_topics_and_payloads():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)  # Increased timeout
    
    try:
        sock.connect(("148.113.9.237", 1883))
        
        # CONNECT packet with clean session
        client_id = b"zomeye_scanner_001"
        connect = bytearray()
        connect.append(0x10)  # CONNECT
        connect.append(12 + len(client_id))  # Remaining length
        connect.extend(b"\x00\x04MQTT\x04\x02\x00\x3c")  # Protocol, flags, keepalive
        connect.extend(struct.pack(">H", len(client_id)))
        connect.extend(client_id)
        
        print("[*] Sending CONNECT packet...")
        sock.send(connect)
        
        # Read CONNACK
        connack = sock.recv(4)
        print(f"[*] CONNACK: {connack.hex(' ')}")
        
        if connack[3] != 0:
            print(f"[-] Auth required (code: {connack[3]})")
            sock.close()
            return
        print("[+] Connected to MQTT broker")
        
        # Subscribe to topics with QoS 1 (more reliable)
        topics_to_subscribe = [
            ("$SYS/#", 1),           # QoS 1
            ("sensor/#", 1),
            ("+/output/#", 1),
            ("#", 1),                # Everything
        ]
        
        packet_id = 1
        all_publishes = []
        
        for topic, qos in topics_to_subscribe:
            subscribe = bytearray()
            # SUBSCRIBE packet with QoS 1
            subscribe.append(0x82)  # SUBSCRIBE
            # Calculate remaining length
            remaining_len = 2 + 2 + len(topic) + 1  # Packet ID (2) + Topic Len (2) + Topic + QoS (1)
            subscribe.append(remaining_len)
            subscribe.extend(struct.pack(">H", packet_id))  # Packet ID
            subscribe.extend(struct.pack(">H", len(topic)))
            subscribe.extend(topic.encode())
            subscribe.append(qos)
            
            print(f"[*] Subscribing to: {topic} (QoS {qos})")
            print(f"    Packet: {subscribe.hex(' ')}")
            sock.send(subscribe)
            
            # Read SUBACK
            try:
                suback = sock.recv(5)
                print(f"    SUBACK: {suback.hex(' ')}")
            except socket.timeout:
                print(f"    SUBACK timeout for {topic}")
            
            packet_id += 1
        
        # Send a PINGREQ to keep connection alive
        print("\n[*] Sending PINGREQ...")
        pingreq = bytearray([0xC0, 0x00])  # PINGREQ
        sock.send(pingreq)
        
        # Wait for PINGRESP
        try:
            pingresp = sock.recv(2)
            print(f"[*] PINGRESP: {pingresp.hex(' ')}")
        except:
            pass
        
        # Collect all PUBLISH messages
        print("\n[*] Collecting retained messages (waiting 10 seconds)...\n")
        
        # Set socket to non-blocking for collecting multiple messages
        sock.settimeout(0.5)
        start_time = time.time()
        messages_received = 0
        
        while time.time() - start_time < 10:  # Wait 10 seconds
            try:
                data = sock.recv(4096)
                if data:
                    messages_received += 1
                    print(f"\n[RECEIVED #{messages_received}] {len(data)} bytes:")
                    print(f"  Hex: {data.hex(' ')}")
                    
                    # Parse all packets in this data chunk
                    offset = 0
                    while offset < len(data):
                        packet_type = data[offset] >> 4
                        
                        if packet_type == 0x03:  # PUBLISH
                            topic, payload = parse_publish_packet(data[offset:])
                            if topic:
                                all_publishes.append((topic, payload))
                                print(f"  Topic: {topic}")
                                print(f"  Payload: {payload[:100]}{'...' if len(payload) > 100 else ''}")
                        elif packet_type == 0x0D:  # PINGRESP
                            print("  PINGRESP received")
                        elif packet_type == 0x09:  # SUBACK
                            print("  SUBACK received")
                        
                        # Move to next packet (simplistic)
                        offset += 1
                        
            except socket.timeout:
                # No data, continue waiting
                continue
            except Exception as e:
                print(f"Error: {e}")
                break
        
        print(f"\n[*] Collected {messages_received} messages")
        
        # Display results
        if all_publishes:
            print("\n" + "="*60)
            print("Topics and their most recent payloads:")
            print("="*60)
            
            for topic, payload in all_publishes:
                print(f"\n    {topic}:")
                # Try to parse as JSON
                try:
                    # Check if it's JSON
                    payload_stripped = payload.strip()
                    if payload_stripped.startswith('{') and payload_stripped.endswith('}'):
                        payload_json = json.loads(payload_stripped)
                        print(json.dumps(payload_json, indent=4))
                    else:
                        print(f"    {payload}")
                except:
                    print(f"    {payload}")
        else:
            print("\n[-] No retained messages found on this broker")
            print("[*] Try publishing a test message first or check broker configuration")
            
        # Try to get version from system topic if available
        for topic, payload in all_publishes:
            if 'version' in topic.lower():
                print(f"\n[+] Broker Version: {payload}")
                break
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()

def parse_publish_packet(data: bytes) -> Tuple[str, str]:
    """Parse MQTT PUBLISH packet and return (topic, payload)"""
    if len(data) < 2:
        return None, None
    
    # Get fixed header
    packet_type = data[0] >> 4
    
    if packet_type != 0x03:
        return None, None
    
    # Decode remaining length
    remaining_length = 0
    multiplier = 1
    offset = 1
    
    while offset < len(data):
        digit = data[offset]
        remaining_length += (digit & 0x7F) * multiplier
        multiplier *= 128
        offset += 1
        if (digit & 0x80) == 0:
            break
    
    # Parse topic length
    if offset + 2 > len(data):
        return None, None
    
    topic_len = (data[offset] << 8) | data[offset + 1]
    offset += 2
    
    # Parse topic
    if offset + topic_len > len(data):
        return None, None
    
    topic = data[offset:offset + topic_len].decode('utf-8', errors='ignore')
    offset += topic_len
    
    # Get QoS to determine if there's a packet ID
    qos = (data[0] & 0x06) >> 1
    if qos > 0:
        # Skip packet ID (2 bytes)
        offset += 2
    
    # Payload is the rest
    payload = data[offset:offset + remaining_length - (topic_len + 2 + (2 if qos > 0 else 0))]
    payload = payload.decode('utf-8', errors='replace')
    
    return topic, payload

def manual_publish_and_subscribe(target_ip: str, port: int = 1883):
    """
    First publish a test message, then subscribe to see if broker sends it
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        sock.connect((target_ip, port))
        
        # CONNECT
        client_id = b"test_publisher"
        connect = bytearray()
        connect.append(0x10)
        connect.append(12 + len(client_id))
        connect.extend(b"\x00\x04MQTT\x04\x02\x00\x3c")
        connect.extend(struct.pack(">H", len(client_id)))
        connect.extend(client_id)
        sock.send(connect)
        
        # CONNACK
        connack = sock.recv(4)
        if connack[3] != 0:
            print(f"Auth required (code: {connack[3]})")
            return
        
        print("[+] Connected")
        
        # Publish a test message with RETAIN flag
        topic = b"test/probe"
        payload = b"Hello from scanner"
        
        publish = bytearray()
        publish.append(0x31)  # PUBLISH with QoS 1 and RETAIN flag
        remaining_len = 2 + len(topic) + 2 + len(payload)  # Topic Len(2) + Topic + Packet ID(2) + Payload
        publish.append(remaining_len)
        publish.extend(struct.pack(">H", len(topic)))
        publish.extend(topic)
        publish.extend(struct.pack(">H", 1))  # Packet ID
        publish.extend(payload)
        
        print(f"[*] Publishing test message to: {topic.decode()}")
        sock.send(publish)
        
        # Wait for PUBACK
        puback = sock.recv(4)
        print(f"[*] PUBACK: {puback.hex(' ')}")
        
        # Now subscribe to see if we get the retained message
        subscribe = bytearray()
        subscribe.append(0x82)
        subscribe.append(2 + 2 + len(topic) + 1)
        subscribe.extend(struct.pack(">H", 2))  # Packet ID
        subscribe.extend(struct.pack(">H", len(topic)))
        subscribe.extend(topic)
        subscribe.append(0)  # QoS 0
        
        print(f"[*] Subscribing to: {topic.decode()}")
        sock.send(subscribe)
        
        # Get SUBACK
        suback = sock.recv(5)
        print(f"[*] SUBACK: {suback.hex(' ')}")
        
        # Get retained message
        try:
            sock.settimeout(2)
            data = sock.recv(256)
            if data:
                print(f"\n[*] Received retained message: {data.hex(' ')}")
                topic, payload = parse_publish_packet(data)
                if topic:
                    print(f"    Topic: {topic}")
                    print(f"    Payload: {payload}")
        except socket.timeout:
            print("[*] No retained message received (broker may not support retain)")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    print("[SCAN MODE 1] Getting all retained messages...")
    get_all_topics_and_payloads()
    
    print("\n[TEST MODE] Testing publish/subscribe...")
    manual_publish_and_subscribe("148.113.9.237", 1883)
