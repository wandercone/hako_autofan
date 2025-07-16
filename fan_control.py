import subprocess
import re
import os
import argparse
import logging
import math
import json
import time
import numpy as np

from colorlog import ColoredFormatter
import yaml
from schema import Schema, And, Or, Use, Optional, SchemaError

STATE_FILE = "/tmp/fancontrol_state.json"
COOLDOWN_PERIOD = 1800  # 30 minutes
NOTIFICATION_METHOD = "unraid"  # default value before config is loaded
CONFIG_FILE = 'config.yaml'
DEBUG = False  # Global flag

handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter(
    fmt='%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    log_colors={
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'yellow',
        'ERROR':    'red',
        'CRITICAL': 'bold_red',
    }
))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False

config_schema = Schema({
    'fallback_sensor': And(str, len),
    'curve_type': And(str, len),
    'fan_min': And(Use(int), lambda n: 0 <= n <= 100),
    'fan_max': And(Use(int), lambda n: 0 <= n <= 100),
    'mechanical_low': And(Use(int), lambda n: n >= 0),
    'mechanical_high': And(Use(int), lambda n: n >= 0),
    'flash_low': And(Use(int), lambda n: n >= 0),
    'flash_high': And(Use(int), lambda n: n >= 0),
    'groups': {
        str: {
            'drives': [And(str, len)],
            Optional('curve_type'): And(str, len),
            Optional('mechanical_low'): And(Use(int), lambda n: n >= 0),
            Optional('mechanical_high'): And(Use(int), lambda n: n >= 0),
            Optional('flash_low'): And(Use(int), lambda n: n >= 0),
            Optional('flash_high'): And(Use(int), lambda n: n >= 0),
            Optional('fan_min'): And(Use(int), lambda n: 0 <= n <= 100),
            Optional('fan_max'): And(Use(int), lambda n: 0 <= n <= 100),
            Optional('pdb'): And(Use(int), lambda n: n >= 0),
        }
    }
})

def validate_and_check_ranges(config):
    config = config_schema.validate(config)

    def check_pair(min_val, max_val, label):
        if min_val >= max_val:
            raise SchemaError(f"{label}: min value ({min_val}) must be less than max value ({max_val})")

    check_pair(config['fan_min'], config['fan_max'], "Fan speed")
    check_pair(config['mechanical_low'], config['mechanical_high'], "Mechanical threshold")
    check_pair(config['flash_low'], config['flash_high'], "Flash threshold")

    for group_name, group in config['groups'].items():
        if 'fan_min' in group and 'fan_max' in group:
            check_pair(group['fan_min'], group['fan_max'], f"{group_name} fan")
        if 'mechanical_low' in group and 'mechanical_high' in group:
            check_pair(group['mechanical_low'], group['mechanical_high'], f"{group_name} mechanical")
        if 'flash_low' in group and 'flash_high' in group:
            check_pair(group['flash_low'], group['flash_high'], f"{group_name} flash")

    return config

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load state file: {e}")
    return {}

def save_state(state):
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        logger.error(f"Failed to save state file: {e}")

def find_by_id_device(serial_fragment, debug=False):
    by_id_path = "/dev/disk/by-id/"
    matches = []
    if not os.path.exists(by_id_path):
        logger.warning(f"{by_id_path} does not exist on this system.")
        return matches

    for entry in os.listdir(by_id_path):
        if '-part' in entry:
            continue
        if serial_fragment in entry:
            full_path = os.path.join(by_id_path, entry)
            if os.path.islink(full_path):
                matches.append(full_path)
            if debug:
                logger.debug(f"Matched {serial_fragment} -> {full_path}")    
    return matches

def get_drive_temp(drive_path, drive_id, debug=False):
    real_device = os.path.realpath(drive_path)
    is_nvme = 'nvme' in os.path.basename(real_device)
    target_path = real_device if is_nvme else drive_path
    cmd = ['smartctl', '-a', target_path] if is_nvme else ['smartctl', '-n', 'standby', '-A', target_path]

    if debug:
        logger.debug(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, check=True
        )
        output = result.stdout
    except subprocess.CalledProcessError as e:
        if is_nvme:
            output = e.stdout
            if debug:
                logger.warning(f"{drive_id} smartctl returned non-zero (code {e.returncode}), but attempting to parse output anyway.")
        else:
            if e.returncode == 2:
                logger.debug(f"Drive {drive_id} is spun down or inactive.")
                return None
            logger.error(f"Error reading {drive_id}: {e}")
            return None
    except Exception as e:
        logger.error(f"Unexpected error reading {drive_id}: {e}")
        return None
    try:
        if is_nvme:
            for line in output.splitlines():
                if "Temperature Sensor 1" in line:
                    match = re.search(r'(\d+)\s+Celsius', line)
                    if match:
                        temp = int(match.group(1))
                        logger.debug(f"Temp from {drive_id} (NVME): {temp} °C")
                        return float(temp)
                elif "Temperature:" in line and "Celsius" in line:
                    match = re.search(r'(\d+)\s+Celsius', line)
                    if match:
                        temp = int(match.group(1))
                        logger.debug(f"Temp from {drive_id} (NVME): {temp} °C")
                        return float(temp)
        else:
            for line in output.splitlines():
                if any(key in line for key in ['Temperature_Celsius', 'Temperature_Internal', 'Airflow_Temperature']):
                    if '(' in line:
                        line = line.split('(')[0]
                    numbers = [int(num) for num in re.findall(r'\b\d{2,3}\b', line)]
                    if numbers:
                        temp = numbers[-1]
                        logger.debug(f"Temp from {drive_id}: {temp} °C")
                        return float(temp)
    except Exception as e:
        logger.error(f"Failed to parse temperature for {drive_id}: {e}")

    return None
    
def get_fallback_temp_ipmi(sensor_name, debug=False):
    try:
        result = subprocess.run(['ipmi-sensors'], capture_output=True, text=True, check=True)
        if debug:
            logger.debug(f"ipmi-sensor output:\n{result.stdout}")
        for line in result.stdout.splitlines():
            if sensor_name.lower() in line.lower():
                logger.debug(f"Matched IPMI line: {line.strip()}")
                fields = [field.strip() for field in line.split('|')]
                if len(fields) >= 5:
                    reading_str = fields[3]
                    try:
                        return float(reading_str)
                    except ValueError:
                        logger.warning(f"[WARN Could not parse temperature from '{reading_str}'")
    except Exception as e:
        logger.error(f" Error querying IPMI sensor '{sensor_name}': {e}")
    return None

def calculate_fan_speed(temp, temp_min, temp_max, fan_min, fan_max, curve_type='linear'):
    curve_type = curve_type.lower()
    if curve_type == 'linear':
        return calculate_fan_speed_linear(temp, temp_min, temp_max, fan_min, fan_max)
    elif curve_type == 'log':
        return calculate_fan_speed_log(temp, temp_min, temp_max, fan_min, fan_max)
    elif curve_type == 'exponential':
        return calculate_fan_speed_exp(temp, temp_min, temp_max, fan_min, fan_max)
    elif curve_type == 'sigmoid':
        return calculate_fan_speed_sigmoid(temp, temp_min, temp_max, fan_min, fan_max)
    elif curve_type == 'custom':
        return calculate_fan_speed_custom(temp, temp_min, temp_max, fan_min, fan_max)        
    else:
        logger.warning(f"Unknown curve_type '{curve_type}', falling back to linear.")
        return calculate_fan_speed_linear(temp, temp_min, temp_max, fan_min, fan_max) 

def calculate_fan_speed_linear(temp, temp_min, temp_max, fan_min, fan_max):
    if temp <= temp_min:
        return fan_min
    elif temp >= temp_max:
        return fan_max
    else:
        ratio = (temp - temp_min) / (temp_max - temp_min)
        speed = fan_min + ratio * (fan_max - fan_min)
        return round(speed) 

def calculate_fan_speed_log(temp, temp_min, temp_max, fan_min, fan_max):
    if temp <= temp_min:
        return fan_min
    elif temp >= temp_max:
        return fan_max
    else:
        norm_temp = (temp - temp_min) / (temp_max - temp_min)
        log_ratio = math.log1p(norm_temp * 9) / math.log1p(9)
        speed = fan_min + log_ratio * (fan_max - fan_min)
        return round(speed)   

def calculate_fan_speed_exp(temp, temp_min, temp_max, fan_min, fan_max, power=3):
    if temp <= temp_min:
        return fan_min
    elif temp >= temp_max:
        return fan_max
    else:
        norm_temp = (temp - temp_min) / (temp_max - temp_min)
        exp_ratio = norm_temp ** power
        return round(fan_min + exp_ratio * (fan_max - fan_min))

def calculate_fan_speed_sigmoid(temp, temp_min, temp_max, fan_min, fan_max, steepness=10):
    if temp <= temp_min:
        return fan_min
    elif temp >= temp_max:
        return fan_max
    else:
        norm_temp = (temp - temp_min) / (temp_max - temp_min)
        sigmoid_ratio = 1 / (1 + math.exp(-steepness * (norm_temp - 0.5)))
        return round(fan_min + sigmoid_ratio * (fan_max - fan_min))
    
def calculate_fan_speed_custom(temp, temp_min, temp_max, fan_min, fan_max):
    if temp <= temp_min:
        return fan_min
    elif temp >= temp_max:
        return fan_max
    else:     
        mid_temp = (temp_min + temp_max) / 2 # midpoint temp (can tweak this)
        fan_mid = (fan_min + fan_max) / 2  # midpoint fan speed (can tweak this)

        if temp <= temp_min:
            return fan_min
        elif temp >= temp_max:
            return fan_max
        elif temp <= mid_temp:
            # Logarithmic-style curve
            norm = (temp - temp_min) / (mid_temp - temp_min)
            log_ratio = math.log1p(norm * 9) / math.log1p(9)
            speed = fan_min + log_ratio * (fan_mid - fan_min)
        else:
            # Exponential-style curve
            norm = (temp - mid_temp) / (temp_max - mid_temp)
            exp_ratio = norm ** 2.5  # tweak power for steepness
            speed = fan_mid + exp_ratio * (fan_max - fan_mid)  
        return round(speed)                       

def notify_host(subject, message, icon="alert", dry_run=False, method=None):
    if method is None:
        method = NOTIFICATION_METHOD
    if method == "none":
        logger.debug(f"Notification suppressed (method=none): {subject} - {message}")
        return
    if dry_run:
        logger.info(f"- DRY RUN - Would send [{method}] notification: [{subject}] {message}")
        return
    if method == "unraid":
        try:
            subprocess.run([
                "/usr/local/emhttp/webGui/scripts/notify",
                "-e", "Unraid Fan Control",
                "-s", subject,
                "-d", message,
                "-i", icon
            ], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to send Unraid notification: {e}")
    elif method == "discord":
        # TODO: Add Discord integration here (webhook, requests)
        logger.info(f"Discord notification not implemented yet: {subject} - {message}")
        pass
    else:
        logger.warning(f"Unknown notification method: {method}")

def main():
    parser = argparse.ArgumentParser(description="Fan Control for HakoForge Chassis")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without making changes")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled.")

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        notify_host("File not found Error", f"Config file '{CONFIG_FILE}' not found.", icon="alert", dry_run=args.dry_run)
        logger.critical(f"Config file '{CONFIG_FILE}' not found.")
        return
    except yaml.YAMLError as e:
        logger.critical(f"Failed to parse YAML config: {e}")
        return

    try:
        config = validate_and_check_ranges(config)
        logger.debug("Config schema and logical validation successful.")
    except SchemaError as e:
        notify_host("Schema Error", f"Config validation error: {e}", icon="alert", dry_run=args.dry_run, method=None)
        logger.critical(f"Config schema validation failed: {e}")
        return

    global FALLBACK_SENSOR, MECHANICAL_LOW, MECHANICAL_HIGH, FLASH_LOW, FLASH_HIGH, DRIVE_IDENTIFIERS

    FALLBACK_SENSOR = config['fallback_sensor']
    MECHANICAL_LOW = config['mechanical_low']
    MECHANICAL_HIGH = config['mechanical_high']
    FLASH_LOW = config['flash_low']
    FLASH_HIGH = config['flash_high']
    DRIVE_IDENTIFIERS = {group: cfg['drives'] for group, cfg in config['groups'].items()}

    any_drive_found = False
    state = load_state()
    timestamp_now = int(time.time())
    
    for group_name, identifiers in DRIVE_IDENTIFIERS.items():
        logger.debug(f"Checking drives in {group_name}")
        group_drives = []

        for ident in identifiers:
            found = find_by_id_device(ident, debug=args.debug)
            if found:
                any_drive_found = True
                for dev_path in found:
                    group_drives.append((dev_path, ident))
            else:
                logger.warning(f"No device found for identifier '{ident}' in {group_name}")

        group_temps = []
        for drive_path, drive_id in group_drives:
            real_device = os.path.realpath(drive_path)
            is_nvme = 'nvme' in os.path.basename(real_device)
            is_mechanical = not is_nvme

            temp = get_drive_temp(drive_path, drive_id, debug=args.debug)
            if temp is not None:
                group_temps.append(temp)
                low_thresh = MECHANICAL_LOW if is_mechanical else FLASH_LOW
                high_thresh = MECHANICAL_HIGH if is_mechanical else FLASH_HIGH

                logger.debug(f"Drive {drive_id} temp {temp:.1f} °C; type: {'Mechanical' if is_mechanical else 'Flash'}")

                if temp > high_thresh:
                    last_alert_time = state.get(drive_id, {}).get("last_alert", 0)
                    if timestamp_now - last_alert_time > COOLDOWN_PERIOD:
                        notify_host(
                            subject=f"High Temperature Alert: {drive_id}",
                            message=f"Drive temperature is high ({temp:.1f} °C), above threshold of {high_thresh} °C.",
                            icon="alert",
                            dry_run=args.dry_run,
                        )
                        state[drive_id] = {"last_alert": timestamp_now}
                    else:
                        logger.debug(f"Suppressed repeat alert for {drive_id} (last sent {timestamp_now - last_alert_time} sec ago)")
                else:
                    if drive_id in state:
                        logger.debug(f"Drive {drive_id} back to normal temperature; clearing alert state.")
                        del state[drive_id]
        group_cfg = config['groups'][group_name]
        fan_min = group_cfg.get('fan_min', config['fan_min'])
        fan_max = group_cfg.get('fan_max', config['fan_max'])
        temp_min = group_cfg.get('mechanical_low', MECHANICAL_LOW)
        temp_max = group_cfg.get('mechanical_high', MECHANICAL_HIGH)
        curve_type = group_cfg.get('curve_type', config.get('curve_type', 'linear'))

        if group_temps:
            avg_temp = sum(group_temps) / len(group_temps)
            logger.info(f"Average temperature for {group_name}: {avg_temp:.1f} °C")

            fan_speed = calculate_fan_speed(avg_temp, temp_min, temp_max, fan_min, fan_max, curve_type=curve_type)
        else:
            logger.info(f"No temperatures found for {group_name}. Setting fan speed to fan_min ({fan_min}%).")
            fan_speed = fan_min

        logger.info(f"Setting fan speed for {group_name}: {fan_speed}%")

        if not args.dry_run:
            # Here, insert code to actually set fan speed, e.g.:
            # set_fan_speed(group_name, fan_speed)
            pass
    if not any_drive_found:
        logger.error("No drives found in any group.")

    save_state(state)

if __name__ == "__main__":
    main()
