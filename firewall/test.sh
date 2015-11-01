#!/bin/bash

NEWRULES=$1
OLDRULES=oldrules

echo "Attenzione, l'ip forwarding (per essere persistente) va settato a mano in /etc/sysctl.conf"


iptables-save > $OLDRULES.v4
ip6tables-save > $OLDRULES.v6

echo "Loading new rules"
bash $NEWRULES

read -p "Mantenere questa configurazione? (y/n) " -t 10 continua
if [ "$continua" != "y" ] 
then
    echo "Ripristino le precedenti"
    iptables-restore < $OLDRULES.v4
    ip6tables-restore < $OLDRULES.v6
else
    echo "Salvo le nuove regole"
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
fi
rm $OLDRULES.v4
rm $OLDRULES.v6
