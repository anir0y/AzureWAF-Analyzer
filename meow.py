import glob, os
import json
import time
from termcolor import colored
import re
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import numpy as np
import tqdm

rootdir = os.getcwd()


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

# cleanup stuff

temp_file = "temp.txt"
db_file = "db.json"

if os.path.exists(temp_file):
        os.remove(temp_file)
        print(colored(f"[+] {temp_file} deleted.", 'red'))
else:
    print(f"{temp_file} does not exist.")

if os.path.exists(db_file):
        os.remove(db_file)
        print(colored(f"[+] {db_file} deleted.", 'red'))
else:
    print(f"{db_file} does not exist.")




print(colored("[+] Gathering all json file in a list", 'green'))
for root, dirs, files in os.walk(rootdir):
    for file in files:
        if file.endswith('.json'):
            #print(os.path.join(root, file))
            filename=os.path.join(root, file)
            f =open("temp.txt", 'a')
            f.write(filename +"\n")
            f.close()  


# dumping into one file
print(colored("[+] Creating DB for analysis", 'green'))
blobs = open(r"temp.txt", 'r')

jsonfiles= blobs.readlines();

pbar = tqdm.tqdm(total=len('temp.txt'), desc=colored("[+] Processing Files", 'green'))

for line in jsonfiles:
    files=(line).rstrip()
    #print(colored(f"[+] Processing File:\t {files}",'blue'))
    
    time.sleep(1)
    filelist=open(files,'r')
    line_list = filelist.readlines();
    for line in line_list:
        f= open('db.json', 'a')
        f.write(line)
        pbar.update()
        pbar.close()
        f.close()
    filelist.close()
    
    

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
       
# print all unique hostnames
for entry in log_entries:
    if entry.strip():
        log_json = json.loads(entry)
        if 'hostname' not in log_json["properties"]:
            ignored_count +=1
            continue
        else:
            hostname = log_json["properties"]["hostname"]
            f = open("hostnames.txt", 'a')
            f.write(hostname + "\r\n")  
            f.close()
    

date = time.strftime("%d/%m/%Y")
# Print the statistics
# print(colored("[+] text", 'green'))

print(colored(f"[+] Analysis Date:\t\t {date}", 'green'))
unique_hostnames = np.unique(np.loadtxt("hostnames.txt", dtype=str))
print(colored("[*] Hostnames: ", 'green'))
for hostname in unique_hostnames:
    print(colored(f"[+] HostName:\t\t\t {hostname}", 'blue'))
print(colored("[*] Brief Summary", 'green'))
print(colored(f"[+] Total Blocked requests:\t {blocked_count}", 'red'))
print(colored(f"[+] Total Matched requests:\t {matched_count}", 'yellow'))
print(colored(f"[+] Total Detected requests:\t {detected_count}", 'blue'))
print(colored(f"[+] Toal Allowed requests:\t {allowed_count}", 'green'))
print(colored(f"[+] Toal Ignored requests:\t {ignored_count}", 'green')) # not sure why I added this.
