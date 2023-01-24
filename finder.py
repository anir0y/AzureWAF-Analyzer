import json

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

ignored_count = 0

reqtid=input('Enter TID: ')


# Iterate through each log entry
for entry in log_entries:
    # Check if the entry is not empty
    if entry.strip():
        # Parse the log entry as JSON
        log_json = json.loads(entry)

        # find TID
        if 'transactionId' not in log_json["properties"]:
            ignored_count +=1
            continue
        else:
            tid = log_json["properties"]["transactionId"]
            uri = log_json["properties"]["requestUri"]
            action = log_json["properties"]["action"]
            message = log_json["properties"]["message"]
            ruleId = log_json["properties"]["ruleId"]

        # Check if the TID exists
        if tid == reqtid:
            print(f" [+] URL:  {uri}")
            print(f" [+] Rule Match:  {action}")
            print(f" [+] Message:  {message}")
            print(f" [+] RuleId {ruleId}")
            print(f" [+] RuleId {tid}")
            continue
        else:
            continue

