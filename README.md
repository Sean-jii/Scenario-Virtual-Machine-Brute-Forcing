# Scenario-Virtual-Machine-Brute-Forcing
In this lab, I go through an incident response scenario to figure out how many devices had brute force attempts on them, which devices were involved, who was doing it, and if anyone was successful in the brute force attempts.

Detection and Analysis

I created an alert rule

Scheduled Query Rule within Log Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) 10 times or more within the last 5 hours.

DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberofFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberofFailures >= 10


After this, I created an incident using this query. The query will run every 4 hours and lookup data from the last 5 hours. It will generate an alert if the number of query results is greater than 0. 

<img width="1502" height="948" alt="• Seani - Create Alert Rule (Brute Force Attempt Detection)" src="https://github.com/user-attachments/assets/6b73b0c5-92ac-4a7a-adb7-89019b3d06b8" />

These were the results from the incident. 

The alert was triggered on 8 different devices by 10 different IP Addresses.

8 different virtual machines were potentially impacted by brute force attempts from 3 different public IP addresses.

<img width="1150" height="700" alt="433656176" src="https://github.com/user-attachments/assets/f9ea3057-dfd5-41a2-a2f5-dc3f98fa6c00" />

To see if any of the IP addresses successfully logged in, I used this query: 

DeviceLogonEvents
| where RemoteIP in("63.250.59.176", "72.241.84.72", "137.184.37.114", "15.204.52.64", "80.64.19.158", "36.134.36.217", "92.63.197.9", "185.156.73.173", "185.156.73.169", "45.136.68.84")
| where ActionType != "LogonFailed"

<img width="1324" height="718" alt="Pasted Graphic 3" src="https://github.com/user-attachments/assets/3b3f2007-ebae-485d-9126-d1a832a5342f" />

None of the remote IP addresses were successful in logging in

—————

Containment, Eradication, and Recovery: 

- Isolated the devices in MDE and ran anti-malware scans on all devices in MDE. 

- NSG was locked down to prevent RDP attempts from the public internet, only allowing my home IP address. (Alternatively I can use bastion host) 

- Policy was proposed to require this for all the VMs going forwards. 

- I changed the status of the alert to active and chose the option “True Positive - Suspicious activity”

<img width="465" height="760" alt="Seanji - Create Alert Rule (Brute Force Attempt Dete" src="https://github.com/user-attachments/assets/3960b3eb-d937-442d-b654-3772c7fa2117" />

- In the comments section for the alert, pasted all the notes above 
