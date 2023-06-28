#!/usr/bin/env bash

set -euo pipefail
set -x


BRIDGE=kmania_br0
QEMU_IF=qemu_tap0
QEMU_MAC="52:55:00:d1:55:01"
RUST_IF=rust_tap1
RUST_MAC="18:70:75:7B:3F:FE"


function reset_net {
 # sudo dhcpcd -k $TAPIF1
 # sudo dhcpcd -x $TAPIF1 # Tell dhcpcd to stop
  sudo pkill dhcpd || true
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
    pkill rs_pxe || true
    reset_net
}
function setup_net {
  sudo ip tuntap add dev "$QEMU_IF" mode tap user "$USER"
  sudo ip tuntap add dev "$RUST_IF" mode tap user "$USER"

  sudo brctl addbr $BRIDGE &> /dev/null
  sudo brctl addif $BRIDGE "$RUST_IF" &> /dev/null
  sudo brctl addif $BRIDGE "$QEMU_IF"  &> /dev/null
  sudo ip link set $BRIDGE up

  sudo ip link set address $RUST_MAC dev "$RUST_IF"
  sudo ip link set address $QEMU_MAC dev "$QEMU_IF"

  sudo ip link set "$RUST_IF" up
  sudo ip link set "$QEMU_IF" up
  sudo ip address add 192.168.33.1/24 broadcast 192.168.33.255 dev kmania_br0


  #sudo bridge fdb add $RUST_MAC dev kmania_br0 dst 192.168.33.111
  #sudo ip addr add 192.168.33.111/24 dev "$RUST_IF"
  #sudo sysctl -w net.ipv4.conf."$RUST_IF".proxy_arp=1
  #sudo arp -s 192.168.33.111 $RUST_MAC -i "$RUST_IF"


  sudo dhcpd -cf ./dhcpcd.conf -lf ./dhcpcd.lease # -d & # -b $BRIDGE
 # sudo dhcpcd -n $TAPIF1 &
}

trap ctrl_c INT
reset_net
setup_net

PAYLOAD=$(cat <<EOF
set -xe
export RUST_BACKTRACE=1
pkill rs_pxe || true
pkill qemu_ipxe || true
rm -f ./target/debug/rs_pxe
cargo build
sudo setcap cap_net_admin,cap_net_raw=eip ./target/debug/rs_pxe
./target/debug/rs_pxe --tap -i "$RUST_IF" --level DEBUG &
qemu-system-x86_64 -enable-kvm -m 1024 -name qemu_ipxe,process=qemu_ipxe -net nic -net tap,ifname="$QEMU_IF",script=no,downscript=no -fda ipxe.dsk -snapshot -serial stdio -display none 
EOF
)


# correct way is to run dhcp server on tapif1 and have raw socket mode enabled?
cargo watch -- bash -c "$PAYLOAD"
