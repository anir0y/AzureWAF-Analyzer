import glob, os
import json
import time
from termcolor import colored
import re
import plotly.graph_objects as go
import matplotlib.pyplot as plt


banner ="""


╔═══════════════════════════════════════════════════════════════════╗
║                      Azure WAF Log Analyzer                       ║
╠═══════════════════════════════════════════════════════════════════╣
║ > meow.py [generated the initial db and gives you basic data]     ║
║ > showbriefedinfo.py [show relevant logs with color highlighting] ║
║ > makemechart.py [creates a bar chart]                            ║
║ > finder.py [finds you log based on TransactionID]                ║
╚═══════════════════════════════════════════════════════════════════╝



dumb script by : @anir0y
"""


print(banner)

hostname = input("Enter the Hostname: ")

# analysis 
# File path of the Azure WAF log file
log_file = "db.json"

# Open the log file
with open(log_file, "r") as f:
    # Read the file contents
    log_data = f.read()

# Split the file contents into a list of log entries
log_entries = log_data.split("\n")

# Initialize variables to store statistics
blocked_count = 0
matched_count = 0
detected_count = 0
allowed_count = 0
ignored_count = 0


# Iterate through each log entry
for entry in log_entries:
    # Check if the entry is not empty
    if entry.strip():
        # Parse the log entry as JSON
        log_json = json.loads(entry)

        # Check if the 'action' key exists in the log entry

        if hostname not in log_json["properties"]["hostname"]: 

            ignored_count +=1
            continue
        else:
            action = log_json["properties"]["action"]
        # Check if the action is "Blocked"
        if action == "Blocked":
            blocked_count += 1
        # Check if the action is "Matched"
        elif action == "Matched":
            matched_count += 1
        elif action == "Detected":
            detected_count +=1
        elif action == "Allowed":
            allowed_count += 1
       

# Print the statistics
# print(colored("[+] text", 'green'))

print(colored("[*] Brief Summary", 'green'))
print(colored(f"[+] Total Blocked requests:\t {blocked_count}", 'red'))
print(colored(f"[+] Total Matched requests:\t {matched_count}", 'yellow'))
print(colored(f"[+] Total Detected requests:\t {detected_count}", 'blue'))
print(colored(f"[+] Toal Allowed requests:\t {allowed_count}", 'green'))
print(colored(f"[+] Toal Ignored requests:\t {ignored_count}", 'green')) # not sure why I added this.

#  Graph

actions = ["Blocked (" + str(blocked_count) + ")", "Matched (" + str(matched_count) + ")","Detected (" + str(detected_count) + ")", "Allowed (" + str(allowed_count) + ")", "Ignored (" + str(ignored_count) + ")" ]
counts = [blocked_count, matched_count, detected_count, allowed_count, ignored_count]
plt.bar(actions, counts)
plt.xlabel("Actions")
plt.ylabel("Counts")
plt.title(" WAF Log Analysis for: " + hostname)
plt.show()
time.sleep(0)
# close the plt
plt.close




