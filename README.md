# Fan Control Script for HakoForge Chassis

This Python script provides automated fan control for the HakoForge chassis by monitoring drive and system temperatures. It uses SMART and IPMI sensor data to adjust fan speeds according to configurable temperature curves, ensuring optimal cooling performance while minimizing noise.

## Features

- Monitors temperatures of mechanical and flash drives via SMART and NVMe interfaces.
- Supports temperature fallback using IPMI sensors.
- Configurable fan speed curves: linear, logarithmic, exponential, sigmoid, and custom.
- Row based drive configuration for granular control per fan wall.

## Requirements

- Python 3.7 or later
- `smartctl` (from `smartmontools`)
- `ipmi-sensors`
- Python packages:
  - `pyyaml`
  - `colorlog`
  - `schema`
  - `numpy`

## Installation

Install Python dependencies with:

```bash
pip install -r requirements.txt
```

Ensure `smartctl` and `ipmi-sensors` are installed on your system.

## Usage

```bash
python fan_control.py [--debug] [--dry-run]
```
### Options

| Option                      | Description                                                      |
|-----------------------------|------------------------------------------------------------------|
| `--dry-run`                 | Show what would happen without making changes                    |
| `--debug`                   | Enable verbose debug logging                                     |

## Configuration

All settings are managed via `config.yaml`, which must reside in the same directory as the script.

## Notification System

Alerts for high temperatures are sent using Unraid's notification system by default. A cooldown period (30 minutes) prevents repeated alerts for the same drive. The notification method can be changed or extended in the script (e.g., integration with Discord).

## Logging

Colored log output is provided for clarity. Logging levels include info, warning, error, and debug, depending on the selected mode.

## State File

The script maintains a state file at `/tmp/fancontrol_state.json` to track alerts and cooldowns between runs.

