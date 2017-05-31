#!/bin/bash
#Script to set up ip tables rules.
#Eryk Szlachetka 18/04/17

interface=$1
echo Interface: $interface. 
echo Setting SSH INPUT..

#Allow established input SSH connection
iptables -A INPUT -i $interface -p tcp --sport 22 -m state --state ESTABLISHED -j DROP

echo Setting SSH OUTPUT..

#Allow NEW,ESTABLISHED output SSH connection
iptables -A OUTPUT -o $interface -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j DROP 

echo Setting HTTP/S OUTPUT
#Allow NEW,ESTABLISHED,RELATED http and https output connections
iptables -A OUTPUT -j DROP -m state --state NEW,ESTABLISHED,RELATED -o $interface -p tcp -m multiport --dports 80,443

echo Setting HTTP/S INPUT
#Allow ESTABLISHED,RELATED http and https input connections
iptables -A INPUT -j DROP -m state --state ESTABLISHED,RELATED -i $interface -p tcp -m multiport --sports 80,443

echo Setting UDP/TCP OUTPUT
#Allow NEW udp/tcp output connections
iptables -A OUTPUT -m state --state NEW -p udp --dport 53 -j DROP
iptables -A OUTPUT -m state --state NEW -p tcp --dport 53 -j DROP

#Allow ESTABLISHED udp/tcp input connections
iptables -A INPUT -m state --state ESTABLISHED -p udp --sport 53 -j DROP
iptables -A INPUT -m state --state ESTABLISHED -p tcp --sport 53 -j DROP
echo Done
echo 
echo New Rules:
iptables -L
