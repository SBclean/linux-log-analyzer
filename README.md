# Linux Log Anomaly Detection & Alerting Tool

This is a lightweight, configurable Python tool for real-time (and one-time) Linux system logs scanning. 
It detects suspicious activity through regular expression, tracks offsets, handles log rotation, 
time and line based log senstivity, and generates a full summary report in a json.

Check Example directory for sample json summary, and sample offset file
Linux directory contains sample config file as well as a large example Linux log file

# Features

- real time (periodic) log scanning 
- Alert generation for:
Failed authentication attempts, Blacklisted user or IP access, consecutive session creation,
priviledge escalation, cron jobs, repeat root user, cron shell, unusual ssport, consecutive user creations, and failed su attempts

- log rotation compatibility via inode tracking
- Timestamped alerts
- Json-based config system
- CLI interface

# Installation
git clone https://github.com/SBclean/linux-log-analyzer.git
cd linux-log-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Usage

One scan:
python3 main.py --logs [logs file path] --config [config file path] --run once

or

python3 main.py -l [...] -c [...] -r once

realtime:
python3 main.py --logs [logs file path] --config [config file path] --run realtime --run-cycle 20 
(default run cycle is 10 seconds for periodic scanning)

or

python3 main.py -l [...] -c [...] - realtime -rc 20

# How it works
The core log scanning process is fed through scanning_logic.py, which first reads user-defined preferences from the configuration JSON. This includes toggling specific alert types on or off, customizing thresholds (such as max failed attempts), and filtering log types based on the config.

Once configured, it provides the log analysis to detection_engine.py, which applies a modular set of detection functions on each log entry based on the active rules. Each detection function is timestamp-aware, and alerts are dynamically generated with detailed metadata including the type, timestamp, and a list of affected line numbers.

When scanning is complete, all alert data is automatically compiled into a timestamped JSON file and stored in a dedicated alerts/ directory. If the directory doesn’t exist, it’s created.

Supporting modules like state_manager.py and global_variables.py provide utility functions for managing offsets, time tracking, and global data sharing across modules.

# More CLI functionality

use --only-alert or -o [choose from list] to only alert the chosen alerts. You can stack this to form a list of specific alerts

use --disable-alert or -d [choose from list] to disable any alert, overriding the config.

use --enabled-alert or e [choose from list] to enable any alert, overriding the config.

both enable and disable are sensitive to each other so for example enabling Authentication_fail_alert the disabling it through the CLI is valid.

