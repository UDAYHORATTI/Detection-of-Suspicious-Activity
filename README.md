# Detection-of-Suspicious-Activity
#This code will parse a log file (like one from a web server or application), and flag potential issues like multiple failed login attempts, brute force attempts, or access from suspicious IP addresses.
import re
from collections import defaultdict
from datetime import datetime

# Sample log lines (could be from a web server or authentication system)
logs = [
    "2025-01-14 08:30:12 user1 Failed login from IP 192.168.1.10",
    "2025-01-14 08:32:25 user2 Successful login from IP 192.168.1.11",
    "2025-01-14 08:33:10 user1 Failed login from IP 192.168.1.10",
    "2025-01-14 08:35:00 user1 Failed login from IP 192.168.1.10",
    "2025-01-14 09:00:15 user3 Failed login from IP 192.168.1.12",
    "2025-01-14 09:10:30 user4 Successful login from IP 192.168.1.13",
    "2025-01-14 09:12:00 user1 Successful login from IP 192.168.1.10",
    "2025-01-14 09:15:00 user1 Suspicious activity detected from IP 10.0.0.1"
]

# Define suspicious activities
suspicious_ip_list = ["192.168.1.10", "10.0.0.1"]  # Example list of suspicious IPs
failed_login_threshold = 3  # Threshold for failed login attempts to flag

# Function to parse the logs
def parse_logs(logs):
    failed_logins = defaultdict(int)
    suspicious_activities = []

    for log in logs:
        # Extract information from log line using regex
        match = re.match(r"(\S+ \S+) (\S+) (.+) from IP (\S+)", log)
        if match:
            timestamp = match.group(1)
            username = match.group(2)
            action = match.group(3)
            ip_address = match.group(4)

            # Convert timestamp to datetime for easier comparison (if needed)
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

            # Detect failed login attempts
            if 'Failed login' in action:
                failed_logins[(username, ip_address)] += 1
                if failed_logins[(username, ip_address)] >= failed_login_threshold:
                    suspicious_activities.append({
                        "timestamp": timestamp,
                        "username": username,
                        "action": "Failed login multiple times",
                        "ip": ip_address
                    })
            # Check for suspicious IP addresses
            if ip_address in suspicious_ip_list:
                suspicious_activities.append({
                    "timestamp": timestamp,
                    "username": username,
                    "action": "Access from suspicious IP",
                    "ip": ip_address
                })
            # Check for other suspicious activity
            if "Suspicious activity" in action:
                suspicious_activities.append({
                    "timestamp": timestamp,
                    "username": username,
                    "action": action,
                    "ip": ip_address
                })

    return suspicious_activities

# Function to display suspicious activities
def display_suspicious_activities(suspicious_activities):
    print("Suspicious Activities Detected:")
    for activity in suspicious_activities:
        print(f"Timestamp: {activity['timestamp']}, Username: {activity['username']}, "
              f"Action: {activity['action']}, IP: {activity['ip']}")

# Parse logs and find suspicious activities
suspicious_activities = parse_logs(logs)

# Display the findings
display_suspicious_activities(suspicious_activities)
