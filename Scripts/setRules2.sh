#!/bin/bash
#Script to set up ip tables rules.
#Pamela Sabio 16/05/17 

echo Setting SSH INPUT..
#Allow established input SSH connection
iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

echo Setting HTTP/S INPUT..
#Allow NEW,ESTABLISHED,RELATED http and https output connections
iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

echo Setting SSH OUTPUT..
iptables -A OUTPUT -o eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

echo Setting HTTP/S OUTPUT
iptables -A OUTPUT -o eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

echo Setting Forwarding..
#setting IP Forwarding for internal network
iptables -A FORWARD -i eth1 -j ACCEPT
iptables -A FORWARD -o eth1 -j ACCEPT

#enabling forwarding on this machine
echo Enabling Forwarding on this machine..
sysctl net.ipv4.ip_forward=1

#
echo Setting Masquerade ..
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

echo Setting PREROUTING details..
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 192.168.12.77:80

echo Done
echo 
echo New Rules:
iptables -L

#Flushing the rules for testing purposes
iptables -F
