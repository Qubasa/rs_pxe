#!/usr/bin/env bash

set -euo pipefail
 
set -x


BRIDGE=kmania_br0
TAPIF=kmania_tap0
TAPIF1=kmania_tap1
IF1_MAC="18:70:75:7B:3F:FE"
TAPIF2=kmania_tap2

function reset_net {
 # sudo dhcpcd -k $TAPIF1
 # sudo dhcpcd -x $TAPIF1 # Tell dhcpcd to stop
  sudo pkill dhcpd || true
  sudo ip link set "$TAPIF" down
  sudo ip link set "$TAPIF1" down
  sudo ip link set "$TAPIF2" down
  sudo ip link set $BRIDGE down
  sudo brctl delif $BRIDGE "$TAPIF"
  sudo brctl delif $BRIDGE "$TAPIF1"
  sudo brctl delif $BRIDGE "$TAPIF2"
  sudo brctl delbr $BRIDGE
  sudo ip tuntap del dev "$TAPIF" mode tap
  sudo ip tuntap del dev "$TAPIF1" mode tap
  sudo ip tuntap del dev "$TAPIF2" mode tap
}
function ctrl_c() {
    echo "** Trapped CTRL-C"
    pkill rs_pxe || true
    reset_net
}
function setup_net {
  sudo ip tuntap add dev "$TAPIF" mode tap user "$USER"
  sudo ip tuntap add dev "$TAPIF1" mode tap user "$USER"
  sudo ip tuntap add dev "$TAPIF2" mode tap user "$USER"
  sudo brctl addbr $BRIDGE &> /dev/null
  sudo brctl addif $BRIDGE $TAPIF1 &> /dev/null
  sudo brctl addif $BRIDGE $TAPIF2 &> /dev/null
  sudo brctl addif $BRIDGE "$TAPIF"
  sudo ip link set $BRIDGE up
  sudo ip link set $TAPIF2 up
  sudo ip link set $TAPIF1 up
  sudo ip link set "$TAPIF" up
  sudo ip address add 192.168.33.1/24 broadcast 192.168.33.255 dev kmania_br0
  #sudo ip addr add 192.168.33.111/24 dev $TAPIF1
  sudo ip link set address $IF1_MAC dev $TAPIF1
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
rm -f ./target/debug/rs_pxe
cargo build
sudo setcap cap_net_admin,cap_net_raw=eip ./target/debug/rs_pxe
./target/debug/rs_pxe --raw "$TAPIF1"  --mac "$IF1_MAC" --ip "192.168.33.111" & # --mac "98:fa:9b:4b:b2:c4" 
qemu-system-x86_64 -enable-kvm -m 1024 -net nic -net tap,ifname="$TAPIF",script=no,downscript=no -fda ipxe.dsk -snapshot -serial stdio -display none 
EOF
)
# correct way is to run dhcp server on tapif1 and have raw socket mode enabled?
cargo watch -- bash -c "$PAYLOAD"
