#!/usr/bin/env bash

set -euo pipefail
 
set -x

LAN=enp2s0
BRIDGE=kmania_br0
TAPIF=kmania_tap0


function reset_net {
  sudo dhcpcd -k $BRIDGE
  sudo ip link set "$TAPIF" down
  sudo ip link set $BRIDGE down
  sudo brctl delif $BRIDGE "$TAPIF"
  sudo brctl delbr $BRIDGE
  sudo ip tuntap del dev "$TAPIF" mode tap
}
function ctrl_c() {
    echo "** Trapped CTRL-C"
    reset_net
    pkill rs_pxe || true
}
function setup_net {
  sudo ip tuntap add dev "$TAPIF" mode tap user "$USER"
  sudo brctl addbr $BRIDGE &> /dev/null
  sudo brctl addif $BRIDGE $LAN &> /dev/null
  sudo brctl addif $BRIDGE "$TAPIF"
  sudo ip link set $BRIDGE up
  sudo ip link set $LAN up
  sudo ip link set "$TAPIF" up
  sudo dhcpcd -n $BRIDGE
}

trap ctrl_c INT
setup_net

PAYLOAD=$(cat <<EOF
set -xe
export RUST_BACKTRACE=1
pkill rs_pxe || true
cargo build
sudo setcap cap_net_admin,cap_net_raw=eip ./target/debug/rs_pxe
./target/debug/rs_pxe --raw "$LAN" --mac "18:70:75:7B:3F:FE"  --ip "192.168.178.97" & #  --mac "98:fa:9b:4b:b2:c4"
qemu-system-x86_64 -enable-kvm -m 1024 -net nic -net tap,ifname="$TAPIF",script=no,downscript=no -cdrom ipxe.iso -serial stdio -display none 
EOF
)

cargo watch -- bash -c "$PAYLOAD"
