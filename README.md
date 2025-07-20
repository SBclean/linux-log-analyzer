# Linux Log Anomaly Detection & Alerting Tool

This is a lightweight, configurable Python tool for real-time (and once-time) Linux system logs scanning. 
It detects suspicious activity through regular expression, tracks offsets, handles log rotation, 
time and line based log senstivity, and generates a full summary report in a json.

# Features

- real time (periodic) log scanning 
- Alert generation for:
Failed authentication attempts, Blacklisted user or IP access, consecutive session creation, priviledge escalation, cron jobs, repeat root user, cron shell, unusual ssport, consecutive user creations, and failed su attempts

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
The scanning_logic.py opens config and filters user preference, toggling and modifying max attempts for every alert. It then uses detection_engine.py to process every log for the enabled alerts and stores all information when finished in an alerts file with a time stamp. if your computer doesn't have an alerts folder it creates it for you. state_manager and global_variables are purely for json/time function as well as multi variable access through different files.

# More CLI functionality

use --only-alert or -o [choose from list] to only alert the chosen alerts. You can stack this to form a list of specific alerts

use --disable-alert or -d [choose from list] to disable any alert, overriding the config.

use --enabled-alert or e [choose from list] to enable any alert, overriding the config.

both enable and disable are sensitive to each other so for example enabling Authentication_fail_alert the disabling it through the CLI is valid.

