#!/bin/bash
#Script to set up ip tables rules.
#Eryk Szlachetka & Caoimhe Harvey 18/04/17 

#Accepting loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUPUT -o lo -j ACCEPT

echo Setting SSH INPUT..
#Allow established input SSH connection
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

echo Setting SSH OUTPUT..
#Allow NEW,ESTABLISHED output SSH connection
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting HTTP/S INPUT..
#Allow NEW,ESTABLISHED,RELATED http and https output connections
iptables -A INPUT -p tcp -m multiport --dports 80,433,8080 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

echo Setting HTTP/S OUTPUT..
#Allow ESTABLISHED,RELATED http and https input connections
iptables -A OUTPUT -p tcp -m multiport --dports 80,433,8080 -m conntrack --ctstate ESTABLISHED -j ACCEPT

#blocking yahoo
iptables -A OUTPUT -p tcp -d 209.191.88.254 --dport 443 -j ACCEPT

echo Setting UDP/TCP OUTPUT..
#Allow NEW udp/tcp output connections
iptables -A OUTPUT -m state --state NEW -p udp --sport 53 -j ACCEPT
iptables -A OUTPUT -m state --state NEW -p tcp --sport 53 -j ACCEPT

echo Setting UDP/TCP INPUT..
#Allow ESTABLISHED udp/tcp input connections
iptables -A INPUT -m state --state ESTABLISHED -p udp --dport 53 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED -p tcp --dport 53 -j ACCEPT

echo Setting SMTP INPUT..
#Allow SMTP connections INPUT
iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

echo Setting SMTP OUTPUT..
#Allow SMTP connection OUTPUT
iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT

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
#iptables -F
