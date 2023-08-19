#!/usr/bin/env bash

set -euo pipefail


LAN=false
BRIDGE=kmania_br0
QEMU_IF=qemu_tap
RUST_IF=rust_tap

# Initialize local variables
uefi_pxe=false
ipxe=false
none=false
LOG_LEVEL="DEBUG"

# Loop over the arguments
while [[ $# -gt 0 ]]; do
  # Check the argument value
  case $1 in
    --uefi_pxe) # Set uefi_pxe to true if --uefi_pxe is present
      uefi_pxe=true
      ;;
    --ipxe) # Set ipxe to true if --ipxe is present
      ipxe=true
      ;;
      --none) # Set ipxe to true if --ipxe is present
      none=true
      ;;
      --trace) # Set ipxe to true if --ipxe is present
      LOG_LEVEL="TRACE"
      ;;
    -i|--interface) # Set the interface name
      LAN=$2
      echo "Using interface $LAN"
      shift
      ;;
    *) # Ignore other arguments
      ;;
  esac
  # Shift to the next argument
  shift
done

if [[ $LAN == false ]]; then
  echo "Usage: $0 [--uefi_pxe] [--ipxe] [--none] -i <interface>"
  echo "The interface must be specified."
  exit 1
fi

# Check if both arguments are false
if [[ $uefi_pxe == false && $ipxe == false && $none == false ]]; then
  # Print a help text and exit with an error code
  echo "Usage: $0 [--uefi_pxe] [--ipxe] [--none]"
  echo "At least one of the arguments must be specified."
  exit 1
fi


function reset_net {
  sudo dhcpcd -f ./assets/dhcpcd.conf -k $BRIDGE || true
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
  sudo dhcpcd -f ./assets/dhcpcd.conf -n $BRIDGE
}

trap ctrl_c INT
reset_net


FILTER="dhcp or tftp"
if $none; then
  wireshark -Y "$FILTER" -k -i "$LAN" &> /dev/null &
else
  setup_net
  wireshark -Y "$FILTER" -k -i "$QEMU_IF" &> /dev/null &
fi

OVMF="$QEMU_SHARE/edk2-x86_64-code.fd"
PAYLOAD=$(cat <<EOF
set -xe
export RUST_BACKTRACE=1
pkill rs_pxe || true
rm -f ./target/debug/rs_pxe
cargo build
sudo setcap cap_net_admin,cap_net_raw=eip ./target/debug/rs_pxe


./target/debug/rs_pxe -l $LOG_LEVEL --ipxe ./assets/ipxe.pxe --kernel ./assets/kernel.elf --raw -i $LAN --ip 192.168.32.1/24 --mac "36:ff:35:46:e0:eb" &


# IPXE Boot Emulation
if $ipxe; then
  qemu-system-x86_64 -enable-kvm -m 256M \
  -name qemu_ipxe,process=qemu_ipxe \
  -net nic -net tap,ifname="$QEMU_IF",script=no,downscript=no \
  -fda ./assets/ipxe.dsk -snapshot \
  -serial stdio -display none
fi

# UEFI EDK2 Boot Emulation
if $uefi_pxe; then
  qemu-system-x86_64 -enable-kvm -m 256M -nodefaults \
      -name qemu_ipxe,process=qemu_ipxe \
      -net nic -net tap,ifname="$QEMU_IF",script=no,downscript=no \
      -drive if=pflash,format=raw,readonly=on,file=$OVMF \
      -serial stdio -vga none -nographic -monitor none \
      -snapshot
fi
EOF
)

find "." -iname "*.rs" | entr -r -n bash -c "$PAYLOAD"
