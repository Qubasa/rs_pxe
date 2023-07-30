#!/usr/bin/env bash

set -euo pipefail
 
set -x

LAN=enp2s0
BRIDGE=kmania_br0
QEMU_IF=qemu_tap
RUST_IF=rust_tap

function reset_net {
  sudo dhcpcd -k $BRIDGE || true
  sudo ip link set "$QEMU_IF" down || true
  sudo ip link set "$RUST_IF" down || true
  sudo ip link set $BRIDGE down || true
  sudo brctl delif $BRIDGE "$QEMU_IF" || true
  sudo brctl delif $BRIDGE "$RUST_IF" || true
  sudo brctl delbr $BRIDGE || true
  sudo ip tuntap del dev "$QEMU_IF" mode tap || true
  sudo ip tuntap del dev "$RUST_IF" mode tap || true
}
function ctrl_c() {
    echo "** Trapped CTRL-C"
    reset_net
    pkill rs_pxe || true
}

function arp_conf {
  sudo sysctl -w net.ipv4.conf."$1".proxy_arp=1
  sudo sysctl -w net.ipv4.conf."$1".arp_filter=0
  sudo sysctl -w net.ipv4.conf."$1".arp_ignore=0
  sudo sysctl -w net.ipv4.conf."$1".arp_notify=1
  sudo sysctl -w net.ipv4.conf."$1".arp_accept=1
}

function setup_net {
  sudo ip tuntap add dev "$QEMU_IF" mode tap user "$USER"
  sudo ip tuntap add dev "$RUST_IF" mode tap user "$USER"

  sudo brctl addbr $BRIDGE &> /dev/null
  sudo brctl addif $BRIDGE "$RUST_IF" &> /dev/null
  sudo brctl addif $BRIDGE "$QEMU_IF"  &> /dev/null
  sudo brctl addif $BRIDGE $LAN &> /dev/null

  sudo ip link set $BRIDGE promisc on

  sudo ip link set $BRIDGE up
  sudo ip link set $LAN up
  sudo ip link set "$RUST_IF" up
  sudo ip link set "$QEMU_IF" up
  sudo dhcpcd -n $BRIDGE
}

trap ctrl_c INT
#reset_net
#setup_net


#wireshark -k -i "$QEMU_IF" &> /dev/null &
#wireshark -k -i "$RUST_IF" &> /dev/null &
#wireshark -k -i "$BRIDGE" &> /dev/null &

wireshark -k -i "$LAN" &> /dev/null &

PAYLOAD=$(cat <<EOF
set -xe
export RUST_BACKTRACE=1
pkill rs_pxe || true
rm -f ./target/debug/rs_pxe
cargo build
sudo setcap cap_net_admin,cap_net_raw=eip ./target/debug/rs_pxe
./target/debug/rs_pxe -l DEBUG --ipxe ./ipxe.pxe --raw -i $LAN &
#qemu-system-x86_64 -enable-kvm -m 1024 -name qemu_ipxe,process=qemu_ipxe -net nic -net tap,ifname="$QEMU_IF",script=no,downscript=no -fda ipxe.dsk -snapshot -serial stdio -display none 
EOF
)

find "." -iname "*.rs" | entr -r -n bash -c "$PAYLOAD"
# cargo watch -- bash -c "$PAYLOAD"
