#!/bin/bash
NS="scan-ns"
CUSTOM_MAC="00:aa:bb:cc:dd:ee"
IP_ADDR="192.168.1.114"
IP_PREFIX="24"  # or 255.255.255.0
GATEWAY="192.168.1.254"
DNS1="8.8.8.8"
DNS2="1.1.1.1"

# Cleanup
sudo ip netns del $NS 2>/dev/null || true
sudo ip link del macvlan0 2>/dev/null || true

# Create namespace and macvlan
sudo ip netns add $NS
sudo ip link add macvlan0 link eth0 type macvlan mode bridge
sudo ip link set macvlan0 netns $NS

# Set MAC and bring up
sudo ip netns exec $NS ip link set macvlan0 address $CUSTOM_MAC
sudo ip netns exec $NS ip link set macvlan0 up
sudo ip netns exec $NS ip link set lo up

# Manual IP configuration
sudo ip netns exec $NS ip addr add ${IP_ADDR}/${IP_PREFIX} dev macvlan0
sudo ip netns exec $NS ip route add default via $GATEWAY

# DNS configuration
sudo ip netns exec $NS sh -c "cat > /etc/resolv.conf << EOF
nameserver $DNS1
nameserver $DNS2
EOF"

# Show configuration
echo -e "\n=== Network Configuration ==="
sudo ip netns exec $NS ip addr show macvlan0

echo -e "\n=== MAC Address ==="
sudo ip netns exec $NS ip link show macvlan0 | grep ether

echo -e "\n=== IP Address (Manual) ==="
sudo ip netns exec $NS ip -4 addr show macvlan0 | grep inet

echo -e "\n=== Routes ==="
sudo ip netns exec $NS ip route

echo -e "\n=== DNS ==="
sudo ip netns exec $NS cat /etc/resolv.conf

echo -e "\n=== Testing Gateway Connectivity ==="
sudo ip netns exec $NS ping -c 3 -W 1 $GATEWAY

echo -e "\n=== Testing Internet Connectivity ==="
sudo ip netns exec $NS ping -c 3 -W 1 8.8.8.8

echo -e "\n✅ Network namespace '$NS' ready with manual IP ${IP_ADDR}/${IP_PREFIX}"
