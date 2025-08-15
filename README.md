Suricata Alert & Log Analysis Lab
📌 Overview

This project demonstrates how to create, trigger, and analyze Suricata rules using a sample packet capture file. Suricata is an open-source intrusion detection system (IDS), intrusion prevention system (IPS), and network security monitoring tool.
In this lab, I worked with custom rules, processed packet data, and explored both fast.log and eve.json outputs.

🎯 Objectives

Understand the structure of Suricata rules (action, header, and options).

Create and modify custom Suricata detection rules.

Trigger alerts using a .pcap file and Suricata in IDS mode.

Analyze alerts in:

fast.log – Quick, human-readable alert log.

eve.json – Detailed JSON-formatted event log for deeper analysis.

🛠 Tools & Files

Suricata – IDS/IPS & network analysis tool.

sample.pcap – Example network traffic for testing rules.

custom.rules – File containing custom Suricata detection rules.

fast.log – Quick alert log.

eve.json – Detailed event log in JSON format.

jq – Command-line JSON processor.

📂 Lab Workflow
1️⃣ Examine the Custom Rule
cat custom.rules


Example Rule:

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GET on wire"; flow:established,to_server; content:"GET"; http_method; sid:12345; rev:3;)


Breakdown:

Action: alert

Protocol: http

Source → Destination: $HOME_NET any → $EXTERNAL_NET any

Options: msg, flow, content, sid, rev

2️⃣ Run Suricata with Custom Rule
sudo suricata -r sample.pcap -S custom.rules -k none


-r → Read packets from file.

-S → Load custom rule file.

-k none → Disable checksum validation.

3️⃣ View Quick Alerts (fast.log)
cat /var/log/suricata/fast.log


Example Output:

11/23/2022-12:38:34.624866 [**] [1:12345:3] GET on wire [**] {TCP} 172.21.224.2:49652 -> 142.250.1.139:80

4️⃣ Analyze Detailed Logs (eve.json)
jq . /var/log/suricata/eve.json | less


Extract specific fields:

jq -c "[.timestamp,.flow_id,.alert.signature,.proto,.dest_ip]" /var/log/suricata/eve.json


Filter by flow_id:

jq "select(.flow_id==14500150016149)" /var/log/suricata/eve.json

📊 Key Learnings

Rule structure: Action → Header → Options.

fast.log is good for quick checks but eve.json is better for detailed analysis.

flow_id helps correlate events in the same network conversation.

Suricata variables like $HOME_NET and $EXTERNAL_NET simplify rule writing.
