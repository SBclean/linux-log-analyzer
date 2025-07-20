import re
from datetime import *
import global_variables
import datetime

#function specific global variables for tracking
sessions = {} #session tracking
counters = {"counter1": [], "counter2": [], "counter3": [], "counter4":[]} #references to old global_variables.logs for alert evaluation
reference_lines = {"reference_line1": None, "reference_line2": None, "reference_line3": None, "reference_line4": None} #references to old global_variables.logs for alert evaulation


#Define alert functions
def Authentication_fail_alert(line, MAX_AUTH_FAIL) -> None:
    from state_manager import time_difference
    global counters, reference_lines
    auth_f = re.compile(r'Failed password for invalid user \w+')
    failed_su4 = re.compile(r'combo sshd\(\w+\)\[\d+\]: authentication failure;')
    new_line = None


    if auth_f.search(line) or failed_su4.search(line):

        if reference_lines["reference_line1"] is None:
            reference_lines["reference_line1"] = line
            counters["counter1"].append((global_variables.scanning, 'f_alert'))
        else:
            new_line = line

        if reference_lines["reference_line1"] != new_line and new_line is not None:
            if (time_difference(reference_lines["reference_line1"], new_line, Authentication_fail_alert)) and (global_variables.scanning - counters["counter1"][-1][0] <= 10):
                counters["counter1"].append((global_variables.scanning, 'f_alert'))
                reference_lines["reference_line1"] = new_line
            else:
                counters["counter1"] = []
                reference_lines["reference_line1"] = None

        if len(counters["counter1"]) >= MAX_AUTH_FAIL:
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")

            global_variables.logs["detected authentication fails"] += 1
            global_variables.alerts += 1
            global_variables.alert_lines.append(('1', global_variables.scanning, formatted_datetime))
            counters["counter1"] = []
            reference_lines["reference_line1"] = None

    else:
        if counters["counter1"] != []:
            if global_variables.scanning - counters["counter1"][-1][0] > 10 and not time_difference(reference_lines["reference_line1"], line, Authentication_fail_alert):
                counters["counter1"] = []
                reference_lines["reference_line1"] = None
        


def Blacklisted_alert(line, BLACK_LISTED_IPS, BLACK_LISTED_USERS) -> None:
    blacklist = re.compile(r'Accepted password for (\w+) from (\d{1,3}(?:\.\d{1,3}){3})')
    blacklisted_IPs = BLACK_LISTED_IPS
    blacklisted_users = BLACK_LISTED_USERS
            
    if blacklist.search(line):
        split_line = line.split()

        for IP, user in zip(blacklisted_IPs, blacklisted_users):
                    if IP in split_line or user in split_line:
                        current_datetime = datetime.now()
                        formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")

                        global_variables.alerts += 1
                        global_variables.alert_lines.append(('2', global_variables.scanning, formatted_datetime))
                        global_variables.logs['detected blacklist accesses'] += 1


def Consecutive_sessions_alert(line) -> None:
    global sessions
    session = re.compile(r'Accepted password for (\w+) from (\d{1,3}(?:\.\d{1,3}){3})')
    
    if session.search(line):
        split_line = line.split()
        sessions[global_variables.scanning] = split_line[2]

        if len(sessions) >= 2:
                session1 = sessions[global_variables.scanning].split(':')
                session2 = sessions[global_variables.scanning - 1].split(':')

                for i in range(3):
                    if i != 3:
                        if session1[i] != session2[i]:
                            sessions = []
                            break

                    elif i == 3:
                        if int(session1[i]) - int(session2[i]) < 8:
                            current_datetime = datetime.now()
                            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
                            global_variables.alerts += 1
                            global_variables.alert_lines.append(('3', global_variables.scanning, formatted_datetime))
                            global_variables.logs['detected consecutive session creations'] += 1
    else:
        if len(sessions) > 1:
            session_n = list(sessions.keys())
            if session_n[0] != session_n[1]-1 or session_n[0] != session_n[1] + 1:
                sessions = {}


def Priviledge_escalation_alert(line) -> None:
    priviledge_list = [r'sudo[:]', r'USER=root', r'COMMAND=/bin/bash', r'COMMAND=bash', r'COMMAND=wget', r'COMMAND=curl'
                       r'COMMAND=sh', r'COMMAND=nc', r'COMMAND=python', r'COMMAND=perl']
    compiled_priv = [re.compile(p) for p in priviledge_list]
    true_count = sum(1 for pattern in compiled_priv if pattern.search(line))
    
    if true_count >= 2:   
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
        global_variables.alerts += 1
        global_variables.alert_lines.append(('4', global_variables.scanning, formatted_datetime))
        global_variables.logs['detected priviledge escalations'] += 1
        true_count = 0


def Cron_usage_alert(line, suspicious_keywords)-> None:
    cron = re.compile(r'CRON\[\d+\]:', re.IGNORECASE)

    if cron.search(line):
        cron_command = re.search(r'CMD \(\w+', line)
        cmd = cron_command.group(1)
        
        if any(sus in cmd for sus in suspicious_keywords):
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
            global_variables.alerts += 1
            global_variables.alert_lines.append(('5', global_variables.scanning, formatted_datetime))
            global_variables.logs['detected malicious crons'] += 1


def Repeat_root_alert(line, REPEAT_ROOT)-> None:
    from state_manager import time_difference
    global counters, reference_lines
    re_ro = re.compile(r'Acceped password for root from (\d{1,3}(?:\.\d{1,3}){3})')
    new_line = None

    if re_ro.search(line):

        if reference_lines["reference_line2"] is None:
            reference_lines["reference_line2"] = line
            counters["counter2"].append((global_variables.scanning, 'f_alert'))
        else:
            new_line = line

        if reference_lines["reference_line2"] != new_line and new_line is not None:
            if (time_difference(reference_lines["reference_line2"], new_line, Repeat_root_alert)) and (global_variables.scanning - counters["counter2"][-1][0] <= 8):
                counters["counter2"].append((global_variables.scanning, 'f_alert'))
                reference_lines["reference_line2"] = new_line
            else:
                counters["counter2"] = []
                reference_lines["reference_line2"] = None

        if len(counters["counter2"]) >= REPEAT_ROOT:
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
            global_variables.logs["detected repeat root accesses"] += 1
            global_variables.alerts += 1
            global_variables.alert_lines.append(('6', global_variables.scanning, formatted_datetime))
            counters["counter2"] = []
            reference_lines["reference_line2"] = None

    else:
        if counters["counter2"] != []:
            if global_variables.scanning - counters["counter2"][-1][0] > 8 and not time_difference(reference_lines["reference_line2"], line, Repeat_root_alert):
                counters["counter2"] = []
                reference_lines["reference_line2"] = None


def Cron_shell_alert(line)-> None:
    cron_s1 = re.compile(r'CRON\[\d+\]: \(\w+\) CMD \(bash -i >& /\d+/\d+/(\d{1,3}(?:\.\d{1,3}){3})\)')
    cron_s2 = re.compile(r'CRON\[\d+\]: \(\w+\) CMD \(sh \w+.sh\)')

    if cron_s1.search(line) or cron_s2.search(line):
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
            global_variables.alerts += 1
            global_variables.alert_lines.append(('7', global_variables.scanning, formatted_datetime))
            global_variables.logs['detected cron shells'] += 1


def Unusual_ssport_alert(line)-> None:
    uns_ss = re.compile(r'Accepted password for \w+ from (\d{1,3}(?:\.\d{1,3}){3}) port [^22]')

    if uns_ss.search(line):
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
            global_variables.alerts += 1
            global_variables.alert_lines.append(('8', global_variables.scanning, formatted_datetime))
            global_variables.logs['detected unusual ssh port'] += 1


def Consecutive_users_alert(line, MAX_USER_CREATION)-> None:
    from state_manager import time_difference
    global counters, reference_lines
    user_c1 = re.compile(r'useradd\[\d+\]: new user: name=\w+, UID=\d+, GID=\d+')
    user_c2 =  re.compile(r'useradd\[\d+\]: adder user \'\w+\'')
    new_line = None

    if user_c1.search(line) or user_c2.search(line):
        if reference_lines["reference_line3"] is None:
            reference_lines["reference_line3"] = line
            counters["counter3"].append((global_variables.scanning, 'f_alert'))
        else:
            new_line = line

        if reference_lines["reference_line3"] != new_line and new_line is not None:
            if (time_difference(reference_lines["reference_line3"], new_line, Consecutive_users_alert)) and (1 <= global_variables.scanning - counters["counter3"][-1][0] <= 20):
                counters["counter3"].append((global_variables.scanning, 'f_alert'))
                reference_lines["reference_line3"] = new_line
            else:
                counters["counter3"] = []
                reference_lines["reference_line3"] = None

        if len(counters["counter3"]) >= MAX_USER_CREATION:
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
        
            global_variables.logs["detected consecutive user creations"] += 1
            global_variables.alerts += 1
            global_variables.alert_lines.append(('9', global_variables.scanning, formatted_datetime))
            counters["counter3"] = []
            reference_lines["reference_line3"] = None

    else:
        if counters["counter3"] != []:
            if global_variables.scanning - counters["counter3"][-1][0] > 20 and not time_difference(reference_lines["reference_line3"], line, Consecutive_users_alert):
                counters["counter3"] = []
                reference_lines["reference_line3"] = None

    
def Reverse_shell_alert(line)-> None:
    re_sh1 = re.compile(r'bash\[\d+\]: bash -i >& /dev/tcp')
    re_sh2 = re.compile(r'bash\[\d+\]: python -c \'\w+')
    re_sh3 = re.compile(r'bash\[\d+\] nc -e /bin/bash')

    if re_sh1.search(line) or re_sh2.search(line) or re_sh3.search(line):
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")
            global_variables.alerts += 1
            global_variables.alert_lines.append(('10', global_variables.scanning, formatted_datetime))
            global_variables.logs['detected reverse shells'] += 1


def Failed_su_attempt(line, SU_FAIL_MAX)-> None:
    from state_manager import time_difference
    global counters, reference_lines
    failed_su1 = re.compile(r'hostname su\[\d+\]: pam_authenticate: Authentication failure')
    failed_su2 = re.compile(r'hostname su\[\d+\]: FAILED SU')
    failed_su3 = re.compile(r'hostname su\[\d+\]: pam_unix\(su:auth\)')
    new_line = None


    if failed_su1.search(line) or failed_su2.search(line) or failed_su3.search(line):
        if reference_lines["reference_line4"] is None:
            reference_lines["reference_line4"] = line
            counters["counter4"].append((global_variables.scanning, 'f_alert'))
        else:
            new_line = line
        # print("here it is:", counters["counter4"])
        # print("number:", len(counters["counter4"]), "counter4: ", counters["counter4"])
        # print("reference", reference_lines["reference_line4"], "newline:", new_line)

        if reference_lines["reference_line4"] != new_line and new_line is not None:
            if (time_difference(reference_lines["reference_line4"], new_line, Failed_su_attempt)) and (1 <= global_variables.scanning - counters["counter4"][-1][0] <= 7):
                counters["counter4"].append((global_variables.scanning, 'f_alert'))
                reference_lines["reference_line4"] = new_line
            else:
                counters["counter4"] = []
                reference_lines["reference_line4"] = None

        if len(counters["counter4"]) >= SU_FAIL_MAX:
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%Y-%m-%d-%H%M%S")

            global_variables.logs["detected SU attempts"] += 1
            global_variables.alerts += 1
            global_variables.alert_lines.append(('11', global_variables.scanning, formatted_datetime))
            counters["counter4"] = []
            reference_lines["reference_line4"] = None

    else:
        if counters["counter4"] != []:
            if global_variables.scanning - counters["counter4"][-1][0] > 7 and not time_difference(reference_lines["reference_line4"], line, Failed_su_attempt):
                counters["counter4"] = []
                reference_lines["reference_line4"] = None



    

    

    




