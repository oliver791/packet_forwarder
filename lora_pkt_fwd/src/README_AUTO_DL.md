# LoRa Packet Forwarder — Dual Mode (Normal + Auto-DL)

Fork of Semtech's [packet_forwarder](https://github.com/Lora-net/packet_forwarder), modified to support **two operating modes** within a single binary:

- **Normal Mode**: standard packet forwarder behaviour (uplink + server-driven downlinks)
- **Auto-DL Mode**: continuous transmission of random downlink packets, useful for RF testing, range measurements and TX chain stress-testing

## Added Features

- Mode selection via command-line argument (`-a` / `--auto-dl`)
- Configurable TX parameters (power, SF, frequency, payload size)
- Automatic CSV logging (`gateway_log.csv`) for both modes (received uplinks and transmitted downlinks)
- Built-in help (`-h` / `--help`

## Prerequisites

- Raspberry Pi (tested on Pi 3/4/Zero 2W)
- Compatible LoRa concentrator (SX1301/SX1257 — e.g. RAK831, IMST iC880A, EMB-LR1301-mPCIe / Arduino Pro Gateway…)
- [Raspberry OS Bookworm](https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2023-10-10/) (tested on the linked version)
- [lora_gateway](https://github.com/Lora-net/lora_gateway) (Semtech HAL v5.0.1) compiled beforehand
- Helper scripts from [nondetalle/loragw](https://github.com/nondetalle/loragw) (`start.sh`, `embConfigs.sh`, `lora_pkt_fwd.service`)
 
## Usage

```
# Help
./lora_pkt_fwd --help

# Normal Mode
./lora_pkt_fwd

# Auto-DL Mode
./lora_pkt_fwd -a [power] [sf] [freq] [size]

```
## Examples

```
# Auto-DL with all default parameters
./lora_pkt_fwd -a

# 20 dBm, SF12, 869.525 MHz, 50-byte payload
./lora_pkt_fwd -a 20 12 869525000 50

# 14 dBm, SF7, 868.1 MHz, 100-byte payload
./lora_pkt_fwd --auto-dl 14 7 868100000 100


```

## CSV Logging

The file gateway_log.csv is automatically created in the working directory.

##Warning

⚠️ Auto-DL mode transmits continuously on the EU868 band. Comply with local regulations regarding duty-cycle and transmission power limits. This mode is intended for testing in controlled environments only.

## Based on

Semtech packet_forwarder v4.0.1
Semtech lora_gateway (HAL) v5.0.1

## License

This project retains the original Semtech license (Revised BSD License). See the LICENSE file.