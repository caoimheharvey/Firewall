#!/bin/bash
#Script to set up ip tables rules.
#Eryk Szlachetka, Pamela Sabio & Caoimhe Harvey 18/04/17 

echo Setting SSH INPUT..
#Allow established input SSH connection
iptables -A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp  --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting SSH OUTPUT..
#Allow NEW,ESTABLISHED output SSH connection
iptables -A OUTPUT -p tcp -m tcp  --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting HTTP/S INPUT..
#Allow NEW,ESTABLISHED,RELATED http and https output connections
iptables -A INPUT -p tcp -m multiport --dports 80,433 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --sports 80,433 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting HTTP/S OUTPUT..
#Allow ESTABLISHED,RELATED http and https input connections
iptables -A OUTPUT -p tcp -m multiport --sports 80,433 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m multiport --sports 80,433 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting UDP/TCP OUTPUT..
#Allow NEW udp/tcp output connections
iptables -A OUTPUT -m state --state NEW -p udp --sport 53 -j ACCEPT
iptables -A OUTPUT -m state --state NEW -p tcp --sport 53 -j ACCEPT

echo Setting UDP/TCP INPUT..
#Allow ESTABLISHED udp/tcp input connections
iptables -A INPUT -m state --state NEW,ESTABLISHED -p udp --dport 53 -j ACCEPT
iptables -A INPUT -m state --state NEW,ESTABLISHED -p tcp --dport 53 -j ACCEPT

echo Setting SMTP INPUT..
#Allow SMTP connections INPUT
iptables -A INPUT -p tcp -m tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting SMTP OUTPUT..
#Allow SMTP connection OUTPUT
iptables -A OUTPUT -p tcp -m tcp --sport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting Forwarding..
#setting IP Forwarding for internal network
iptables -A FORWARD -i eth0 -j ACCEPT
iptables -A FORWARD -o eth0 -j ACCEPT

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
