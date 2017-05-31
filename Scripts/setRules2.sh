#!/bin/bash
#Caoimhe Harvey 
#May 28 2017
#Redoing IP tables code to fix accepting bug after connection is dropped

#echo Loading setRules attempt 2 ...

#echo accepting http/s connections...
#HTTP/S
#iptables -A INPUT -i eth0 -p tcp -m multiport --dport 80,443,8080 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o eth0 -p tcp -m multiport --sport 80,443,8080 -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT -i lo -j ACCEPT

#echo accepting tcp/udp connections...
#TCP/UDP
#iptables -A OUTPUT -o eth0 -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -i eth0 -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

#SMTP

#SSH


echo Attempt 3
echo DROPPING CONNECTIONS
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP

echo SETTING INCOMING CONNECTION - INTERNET
iptables -A INPUT --in-interface lo -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dport 80,443,8080,22 -j ACCEPT

echo Allowing Responses
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

