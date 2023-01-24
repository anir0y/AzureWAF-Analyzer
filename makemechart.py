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
        if 'action' not in log_json["properties"]:
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
print(colored("=======================================", 'white'))
print(colored(("Total Blocked requests:", blocked_count), 'red'))
print(colored(("Total Matched requests:", matched_count), 'yellow'))
print(colored(("Total Detected requests:", detected_count), 'blue'))
print(colored(("Toal Allowed requests:", allowed_count), 'green'))
#print(colored(("Toal Ignored requests", ignored_count), 'green')) # not sure why I added this.
print(colored("=======================================", 'white'))
print("[+] analysis done")

# Boring Graph! no able to figure out how to print the occourance so used diffrent lib
#actions = ["Blocked", "Matched", "Detected", "Allowed"]
#counts = [blocked_count, matched_count, detected_count, allowed_count]
#plt.bar(actions, counts)
#plt.xlabel("Actions")
#plt.ylabel("Counts")
#plt.title("Azure WAF Log Analysis")
#plt.show()




# Create the bar chart with browser stuffs

fig = go.Figure(data=[go.Bar(x=["Blocked (" + str(blocked_count) + ")", "Matched (" + str(matched_count) + ")","Detected (" + str(detected_count) + ")", "Allowed (" + str(allowed_count) + ")" ], y=[blocked_count, matched_count, detected_count, allowed_count])])
# Show the chart
fig.show()




