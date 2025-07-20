import os
from datetime import *
import json
import global_variables

#creates a json for storing offsets, file names, and inodes
def offset_file(saved_file_inodes):
    offset_file = "offset.json"

    if os.path.isfile(offset_file):
        with open(offset_file, 'r') as f:
            saved_file_inodes = {int(k): tuple(v) for k, v 
                                 in json.load(f).items()}
    else:
        saved_file_inodes = {}
    
    return saved_file_inodes


#creates a json for storing log alerts summary
def saved_alerts(scanning, alerts, logs, alert_lines):
    directory = "alerts"
    os.makedirs(directory, exist_ok=True)
        
    current_datetime = datetime.now()
    formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
    file_name = "alerts_" + formatted_datetime + ".json"
    full_file_path = os.path.join(directory, file_name)

    export_data = {
        "summary_metadata":{
            "timestamps": str(current_datetime),
            "log_file": global_variables.log_file,
            "scan_mode": global_variables.scan_mode,
            "number_of_scanned_logs": scanning,
            "total_alerts_detected": alerts,
            "alerts_summary": logs,
            # "alert_lines": alert_lines

        "scanned_offset_start": global_variables.offset_start,
        "scanned_offset_end": global_variables.offset_end,

        },

        "alert_details":{
            "Authentication_fail_alerts": {
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '1'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '1']
            },

            "Blacklist_access_alerts:":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '2'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '2']
            },
            "Consecution_session_creation_alert":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '3'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '3']
            },
            "Priviledge_escalation_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '4'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '4']
            },
            "Cron_usage_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '5'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '5']
            },
            "Repeat_root_user_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '6'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '6']
            },
            "Cron_shell_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '7'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '7']
            },
            "Unusual_ssport_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '8'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '8']
            },
            "Consecutive_user_creation_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '9'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '9']
            },
            "Reverse_shell_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '10'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '10']
            },
            "Failed_su_attempt_alerts":{
                "line_numbers": [x[1] for x in global_variables.alert_lines if x[0] == '11'],
                "time_stamps":[x[2] for x in global_variables.alert_lines if x[0] == '11']
            }
        }
    }

    with open(full_file_path, 'w') as f:
        json.dump(export_data, f, indent=4)

    if os.path.exists(full_file_path):
        print("✅ File successfully created.")
    else:
        print("❌ File creation failed.")

#calculates time difference for inputed logs
def time_difference(log1, log2, function) -> bool:
    from detection_engine import Authentication_fail_alert,Repeat_root_alert, Consecutive_users_alert, Failed_su_attempt
    split1, split2 = log1.split(), log2.split()
    time_1, time_2 = split1[2].split(":"), split2[2].split(":")
    total_minutes_1 = (int(time_1[0])*60) + int(time_1[1]) + (int(time_1[2])/60)
    total_minutes_2 = (int(time_2[0])*60) + int(time_2[1]) + (int(time_2[2])/60)
    difference = abs(total_minutes_1 - total_minutes_2)
    
    day_1, day2 = split1[1], split2[1]
    if day_1 != day2:
        return False
    elif split1[0] != split2[0]:
        return False

    if function == Authentication_fail_alert:

        if 2 <= difference <= 10:
            return True
        else: 
            return False
    
    elif function == Repeat_root_alert:

        if 2<= difference <= 5:
            return True
        else:
            return False

    elif function == Consecutive_users_alert:

        if 5 <= difference <= 20:
            return True
        else:
            return False

    elif function == Failed_su_attempt:
        print(difference)
        if 0 <= difference <= 5:
            return True
        else:
            return False



