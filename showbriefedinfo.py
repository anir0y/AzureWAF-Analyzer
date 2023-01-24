import re
import json
from termcolor import colored

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
# Open the text file for reading
with open('db.json', 'r') as f:
    # Read the contents of the file
    text = f.read()

# Use regular expression to match the starting and ending lines of each section
pattern = r'"timeStamp":\s*"(.*)",\s*"resourceId":\s*"(.*)",\s*"operationName":\s*"(.*)",\s*"category":\s*"(.*)",\s*"properties":\s*{"instanceId":\s*"(.*)",\s*"clientIp":\s*"(.*)",\s*"requestUri":\s*"(.*)",\s*"ruleSetType":\s*"(.*)",\s*"ruleId":\s*"(.*)",\s*"priority":\s*(.*),\s*"message":\s*"(.*)",\s*"action":\s*"(.*)",\s*"hostname":\s*"(.*)",\s*"transactionId":\s*"(.*)",\s*"policyId":\s*"(.*)",\s*"policyScope":\s*"(.*)",\s*"policyScopeName":\s*"(.*)",\s*"engine":\s*"(.*)"}'
matches = re.finditer(pattern, text)

# Create a list to hold the JSON objects
json_list = []

# Iterate over the matches
for match in matches:
    # Create a dictionary to hold the data for this match
    json_data = {
        "timeStamp": match.group(1),
        "resourceId": match.group(2),
        "operationName": match.group(3),
        "category": match.group(4),
        "instanceId": match.group(5),
        "clientIp": match.group(6),
        "requestUri": match.group(7),
        "ruleSetType": match.group(8),
        "ruleId": match.group(9),
        "priority": match.group(10),
        "message": match.group(11),
        "action": match.group(12),
        "hostname": match.group(13),
        "transactionId": match.group(14),
        "policyId": match.group(15),
        "policyScope": match.group(16),
        "policyScopeName": match.group(17),
        "engine": match.group(18)
    }
    # Append the dictionary to the list of JSON objects
    json_list.append(json_data)

# Iterate over the list of JSON objects
for obj in json_list:
    action = obj["action"]
    first_word = action.split()[0] #Extracting first word
    timeStamp = obj['timeStamp']
    tid= obj['transactionId']
    requri= obj['requestUri'].split("/")[-1]

    first_word = action.split()[0] #Extracting first word
    if "Matched" in first_word:
        print(colored(f"{first_word} with  Time: {timeStamp} TransactionId: {tid} URL:  {requri}", 'green'))
    elif "Detected" in first_word:
        print(colored(f"{first_word} with  Time: {timeStamp} TransactionId: {tid} URL:  {requri}" , 'yellow'))
    elif "Blocked" in first_word:
        print(colored(f"{first_word} with  Time: {timeStamp} TransactionId: {tid} URL:  {requri}", 'red'))
    elif "Allowed" in first_word:
        print(colored(f"{first_word} with  Time: {timeStamp} TransactionId: {tid} URL:  {requri}", 'blue'))
    else:
        print(first_word)
    
