import json
import argparse
from termcolor import colored

banner="""


┌─────────────────────────────────────────────────────────────┐
│ Azure WAF Log Analyzer v.1.2                                │
│ Script: ShowBriefInfo                                       │
│ UseCase: Filer Alerts based on Hostname and show brief info │
│ run : Enter {hostname} and {action} when asked              │
└─────────────────────────────────────────────────────────────┘

dumb script by : @anir0y
"""


print(banner)
print("Action Filter:")
print(colored("Blocked", 'red'))
print(colored("Detected", 'yellow'))
print(colored("Matched", 'green'))
print(colored("Allowed", 'green'))



# analysis 
# File path of the Azure WAF log file
log_file = "db.json"

# Open the log file
with open(log_file, "r") as f:
    # Read the file contents
    log_data = f.read()

# Split the file contents into a list of log entries
log_entries = log_data.split("\n")

ignored_count = 0


print()
print()
hname = input("Enter the Hostname: ")
reqtid=input('Enter ACTION: ')

# Iterate through each log entry
for entry in log_entries:
    # Check if the entry is not empty
    if entry.strip():
        # Parse the log entry as JSON
        log_json = json.loads(entry)

        # find TID
        if 'action' not in log_json["properties"]:
            ignored_count +=1
            continue
        else:
            tid = log_json["properties"]["action"]
            uri = log_json["properties"]["requestUri"]
            action = log_json["properties"]["action"]
            message = log_json["properties"]["message"]
            ruleId = log_json["properties"]["ruleId"]
            TransactionId = log_json["properties"]["transactionId"]
            hostname = log_json["properties"]["hostname"]

        # Check if the TID exists
        if tid == reqtid:
            if log_json["properties"]["hostname"] == hname:
                print('[*] Match Found')
                print(colored(f" [+] Hostname:   {hostname}", 'yellow'))
                print(colored(f" [+] URL:    {uri}", 'green'))
                print(colored(f" [+] Rule:    {action}", 'yellow'))
                print(f" [+] Message:   {message}")
                print(f" [+] RuleId:    {ruleId}")
                print(f" [+] TransactionId: {TransactionId}")
                continue
            else:
                continue
        else:
            continue

