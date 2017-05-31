#!/bin/bash
#Caoimhe Harvey 
#May 28 2017
#Redoing IP tables code to fix accepting bug after connection is dropped

echo Loading setRules attempt 2 ...
echo  
echo Setting Drop Policy...
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUPUT DROP

echo 
echo accepting http/s connections...
#HTTP/S
iptables -A INPUT -i eth0 -p tcp -m multiport --dport 80,443,8080 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp -m multiport --sport 80,443,8080 -m state --state ESTABLISHED -j ACCEPT

echo 
echo accepting tcp/udp connections...
#TCP/UDP
iptables -A OUTPUT -o eth0 -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

#SMTP

#SSH
