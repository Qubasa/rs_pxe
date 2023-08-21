# Rs_pxe
An 'all in one' command line PXE boot utility. Includes a PXE specific DHCP server and a TFTP server. It uses a RAW_SOCKET to talk to the network. This works on Ethernet as well as Wi-Fi.

## Warning: Alpha Software
This program is still in early stages and needs more hardware testing. Currently, rs_pxe works on the following architectures:
- [x] Intel BIOS Boot with IPv4.
- [ ] Intel UEFI Boot with IPv4. (Currently, in the making)
- [ ] AMD BIOS Boot with IPv4.
- [ ] AMD UEFI Boot with Ipv4.

Rs_pxe does work with Wi-Fi interfaces, however due to its unreliability, packets get reordered or lost more often, which currently breaks the state machine in most cases.

## Example Command
```bash
sudo ./result/bin/rs_pxe  --ipxe assets/ipxe.pxe -k assets/kernel.elf -i enp2s0 --raw
```
With debug logs:
```bash
sudo ./result/bin/rs_pxe -l DEBUG --ipxe assets/ipxe.pxe -k assets/kernel.elf -i enp2s0 --raw
```
To make the binary executable as a normal user. Execute the command below:
```bash
sudo setcap cap_net_admin,cap_net_raw=eip ./target/release/rs_pxe
```

## Install Dependencies

This project uses the [Nix package manager](https://nixos.org/download.html).

If you do not want to install it you can use the 
[nix-portable](https://github.com/DavHau/nix-portable/releases) binary instead.

To drop into the development environment just execute:
```bash
~/Downloads/nix-portable nix develop
```

OR

Install the [Nix package manager](https://nixos.org/download.html) by executing following command:
```bash
sh <(curl -L https://nixos.org/nix/install) --daemon --yes --nix-extra-conf-file ./assets/nix.conf && bash
```

## Development Environment

The command below will spawn a bash shell with all needed dependencies.
```bash
nix develop
```

Then to build the project:
```
cargo build
```
The resulting binary lies in: `target/debug/rs_pxe`

To run tests execute:
```
cargo test
```

You can use a wrapper shell script in the repo. It rebuilds & execute the binary on source changes:
```
./run.sh --none -i enp2s0
```

## Build Binary

To build an executable:
```bash
nix build
```
The resulting binary lies in `result/bin/rs_pxe`

