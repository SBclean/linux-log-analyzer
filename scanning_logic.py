from detection_engine import *
import global_variables
import json
import os


#Dynamic log scanning and exporting. dict: key: inode, value = (filename, current seeker)
def scan_logs(file, config, disabled_alerts=None, enable_alerts=None, Only_alert=None):
    try:
        if disabled_alerts is None:
            disabled_alerts = []
            
        if enable_alerts is None:
            enable_alerts = []


        with open(config, "r") as f:
            config = json.load(f)

            #log thresholds for consecutive type alerts
            MAX_AUTH_FAIL = config["thresholds"]["auth_fail_max"]
            MAX_ROOT_LOGIN = config["thresholds"]["root_login_max"]
            MAX_USER_CREATION = config["thresholds"]["user_creation_max"]
            MAX_SU_FAIL = config["thresholds"]["su_fail_max"]

            #black listed IPs and users
            BLACK_LISTED_IPS = config["blacklist"]["ips"]
            BLACK_LISTED_USERS = config["blacklist"]["users"]

            #cron watch/keywords
            CRON_TOGGLE = config["cron_watch"]["enabled"]
            CRON_KEYWORDS = config["cron_watch"]["keywords"]

            #Alert toggles
            AUTH_FAIL = config["alert_toggles"]["auth_fail"]
            BLACKLIST_LOGIN = config["alert_toggles"]["blacklist_login"]
            SESSION_FLOOD = config["alert_toggles"]["session_flood"]
            PRIV_ESCALATION = config["alert_toggles"]["priv_escalation"]
            MALICIOUS_CRON = config["alert_toggles"]["malicious_cron"]
            REPEAT_ROOT = config["alert_toggles"]["repeat_root"]
            CRON_SHELL = config["alert_toggles"]["cron_shell"]
            UNUSUAL_SSH_PORT = config["alert_toggles"]["unusual_ssh_port"]
            MASS_USER_CREATION = config["alert_toggles"]["mass_user_creation"]
            REVERSE_SHELL = config["alert_toggles"]["reverse_shell"]
            SU_ATTEMPT = config["alert_toggles"]["su_attempt"]

            #Alert toggle dictionary
            ALERT_FUNCTIONS = {
            Authentication_fail_alert: AUTH_FAIL,
            Blacklisted_alert: BLACKLIST_LOGIN,
            Consecutive_sessions_alert: SESSION_FLOOD,
            Priviledge_escalation_alert: PRIV_ESCALATION,
            Cron_usage_alert: MALICIOUS_CRON,
            Repeat_root_alert: REPEAT_ROOT,
            Cron_shell_alert: CRON_SHELL,
            Unusual_ssport_alert: UNUSUAL_SSH_PORT,
            Consecutive_users_alert: MASS_USER_CREATION,
            Reverse_shell_alert: REVERSE_SHELL,
            Failed_su_attempt: SU_ATTEMPT
            }

            #Alert toggle dictionary
            Alert_Parameters = {
            Authentication_fail_alert: MAX_AUTH_FAIL,
            Blacklisted_alert: [BLACK_LISTED_IPS, BLACK_LISTED_USERS],
            Consecutive_sessions_alert: None,
            Priviledge_escalation_alert: None,
            Cron_usage_alert: CRON_KEYWORDS,
            Repeat_root_alert: MAX_ROOT_LOGIN,
            Cron_shell_alert: None,
            Unusual_ssport_alert: None,
            Consecutive_users_alert: MAX_USER_CREATION,
            Reverse_shell_alert: None,
            Failed_su_attempt: MAX_SU_FAIL
            }

            #Toggled alerts
            
            ENABLED_ALERTS = {
                func: toggle for func, toggle in ALERT_FUNCTIONS.items() if toggle == True or str(func) in enable_alerts
            }

            #Config of toggled Alerts
            if Only_alert is None:
                ENABLED_ALERTS_WITH_PARAMETERS = {
                func: parameters for func, parameters in Alert_Parameters.items() 
                if func in ENABLED_ALERTS and str(func) not in disabled_alerts
            }
            else:
                ENABLED_ALERTS_WITH_PARAMETERS = {
                func: parameters for func, parameters in Alert_Parameters.items() 
                if str(func) in Only_alert
            }
            
            f.close()


        filestats = os.stat(file)
        file_inode = filestats.st_ino
        print(file_inode)

        if os.path.isfile("offset.json"):
            with open("offset.json", 'r') as f:
                inodes = json.load(f)
                if str(file_inode) in [x for x in inodes]:
                    seeker = inodes[f"{file_inode}"][1]
                else:
                    seeker = 0
            f.close()
        else:
            seeker = 0

        global_variables.offset_start = seeker

        with open(file, 'rb') as f:
            f.seek(seeker)

            while True:
                line1 = f.readline()
                line = line1.decode("utf-8", errors="ignore")
                print(line)
                global_variables.scanning += 1              

                for key in ENABLED_ALERTS_WITH_PARAMETERS:
                    if ENABLED_ALERTS_WITH_PARAMETERS[key] is None:
                        key(line)

                    elif isinstance(ENABLED_ALERTS_WITH_PARAMETERS[key], list):
                        list1 = ENABLED_ALERTS_WITH_PARAMETERS[key]

                        if key == Blacklisted_alert:
                            key(line, list1[0], list1[1])
                        
                        elif key == Cron_usage_alert:
                            key(line, list1)
                        
                    else:
                        key(line, ENABLED_ALERTS_WITH_PARAMETERS[key])

#                 print(f"""
# ==========Current Summary============
# Number of alerts: {global_variables.alerts}
# Number of logs scanned {global_variables.scanning}

# Advanced detection details:
#                 """)
#                 for k, v in global_variables.logs.items():
#                     print(f"{k}: {v}")

                if line == b'' or global_variables.scanning == 10:
                    seeker = f.tell()                        
                    break
        f.close()

        global_variables.saved_file_inodes[file_inode] = (file, seeker)
        global_variables.offset_end = seeker

        print(f"""
    ==========Final Summary============
    Number of alerts: {global_variables.alerts}
    Number of logs scanned {global_variables.scanning}

    Advanced detection details:
                """)
        for k, v in global_variables.logs.items():
            print(f"{k}: {v}")

        with open("offset.json", "w") as f:
            json.dump({str(x):y for x,y in global_variables.saved_file_inodes.items()}, f, indent=4)
        
        print(f"scanning: {global_variables.scanning}, alerts: {global_variables.alerts}, alert_lines: {global_variables.alert_lines}, offset: {global_variables.saved_file_inodes}")
        
    except Exception as e:
        print("this is the problem: ", e)
        with open("offset.json", "w") as f:
            json.dump({str(x):y for x,y in global_variables.saved_file_inodes.items()}, f, indent=4)