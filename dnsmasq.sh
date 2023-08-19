#!/usr/bin/env bash
sudo ip a a 192.168.32.50/24 dev enp2s0
sudo dnsmasq -d --interface "enp2s0" --dhcp-range "192.168.32.50,192.168.32.100,12h" --port 0 --dhcp-option 3 --dhcp-option 6
