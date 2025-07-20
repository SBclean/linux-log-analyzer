logs = { "detected Authentication fails":0, "detected blacklist accesses":0, "detected priviledge escalations":0,
         'detected consecutive session creations':0, 'detected malicious crons':0,
           'detected repeat root accesses':0, 'detected cron shells':0, 'detected unusual ssh port':0,
         'detected consecutive user creations':0, 'detected reverse shells': 0, 'detected SU attempts':0}
alerts = 0
alert_lines = []
scanning = 0
saved_file_inodes = {}
scan_mode = None
log_file = None
offset_start = None
offset_end = None