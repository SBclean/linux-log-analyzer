if __name__ == "__main__":
    import global_variables
    from scanning_logic import scan_logs
    from state_manager import saved_alerts, offset_file
    import argparse
    import time

    parser = argparse.ArgumentParser(description="Test log files for suspicious activity; Can be done in realtime or once.")
    parser.add_argument("-l", "--logs", required=True, help="The pathfile to the logs")
    parser.add_argument("-c", "--config", required=True, help="The pathfile to the configs" )
    parser.add_argument("-r", "--run", required=True, choices=["realtime", "once"], help="Run the log engine with the choices provided")
    parser.add_argument("-rc", "--run-cycle", default=10, help="realtime scanning scans every X seconds given the input")
    parser.add_argument("-o", "--only-alert", required=False, action="append", choices=[
        "Authentication_fail_alert",
        "Blacklisted_alert",
        "Consecutive_sessions_alert",
        "Priviledge_escalation_alert",
        "Cron_usage_alert",
        "Repeat_root_alert",
        "Cron_shell_alert",
        "Unusual_ssport_alert",
        "Consecutive_users_alert",
        "Reverse_shell_alert",
        "Failed_su_attempt"])
    parser.add_argument("-d", "--disable-alert", required=False, action="append", choices=[
        "Authentication_fail_alert",
        "Blacklisted_alert",
        "Consecutive_sessions_alert",
        "Priviledge_escalation_alert",
        "Cron_usage_alert",
        "Repeat_root_alert",
        "Cron_shell_alert",
        "Unusual_ssport_alert",
        "Consecutive_users_alert",
        "Reverse_shell_alert",
        "Failed_su_attempt"])
    parser.add_argument("-e", "--enable-alert", required=False, action="append", choices=[
        "Authentication_fail_alert",
        "Blacklisted_alert",
        "Consecutive_sessions_alert",
        "Priviledge_escalation_alert",
        "Cron_usage_alert",
        "Repeat_root_alert",
        "Cron_shell_alert",
        "Unusual_ssport_alert",
        "Consecutive_users_alert",
        "Reverse_shell_alert",
        "Failed_su_attempt"])
    
    args = parser.parse_args()
    global_variables.scan_mode = args.run
    global_variables.log_file = args.logs

    #check if offsett json exists
    saved_file_inodes = offset_file(global_variables.saved_file_inodes)

    #call dynamic function and file path+config
    if args.run == "once":
        scan_logs(args.logs, args.config, args.disable_alert, args.enable_alert, args.only_alert)
        print(global_variables.scanning, global_variables.alert_lines, global_variables.saved_file_inodes, global_variables.alert_lines)
        print(args.run)

    elif args.run == "realtime" and args.only_alert is None:
        try:
            while True:
                saved_file_inodes = offset_file(global_variables.saved_file_inodes)
                scan_logs(args.logs, args.config)
                time.sleep(int(args.run_cycle))

        except KeyboardInterrupt:
            print("Ctrl+c detecte, stopped scanning logs")
    
    else: 
        try:
            while True:
                saved_file_inodes = offset_file(saved_file_inodes)
                scan_logs(args.logs, args.config, None, args.only_alert)
                time.sleep(int(args.run_cycle))

        except KeyboardInterrupt:
            print("Ctrl+c detected, stopped scanning logs")

    #Now place json file with  and timestamp folder
    saved_alerts(global_variables.scanning, global_variables.logs, global_variables.saved_file_inodes, global_variables.alert_lines)