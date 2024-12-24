#!/bin/bash 

for i in {1..40000}; do 
    ovsdb-client  transact tcp:10.0.0.11:6643 '["FIREWALL", {"op": "insert", "table": "Rule", "row": {"vlan": ["uuid", "61cb281f-8611-403c-93f4-907f356db765"], "action": "allow", "direction": "ingress", "priority": 100, "protocol": "tcp", "dst_port": '"$i"', "enabled": true } }]' 
done