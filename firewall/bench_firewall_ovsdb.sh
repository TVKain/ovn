#!/bin/bash 

for i in {200..400}; do 

    output=$(ovsdb-client  transact tcp:10.0.0.11:6643 '["FIREWALL", {"op": "insert", "table": "Vlan", "row": {"vlan_id": '$i', "enable_acl": true} }]')

    json=$(echo "$output" | sed "s/'/\"/g")

    # Extract the uuid value using jq
    uuid=$(echo "$json" | jq -r '.[0].uuid[1]')

    for j in {1..20}; do
        ovsdb-client  transact tcp:10.0.0.11:6643 '["FIREWALL", {"op": "insert", "table": "Rule", "row": {"vlan": ["uuid", "'"$uuid"'"], "action": "allow", "direction": "egress", "priority": 100, "protocol": "tcp", "dst_port": '"$j"', "enabled": true } }]' 
    done
done