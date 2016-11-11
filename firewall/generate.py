#!/usr/bin/env python3

import json
import argparse
import sys


def argparser(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Generate firewall rules for UZ servers")
    parser.add_argument('config' , 
                        type=argparse.FileType('r'), 
                        help="The configuration file",
                        )
    parser.add_argument('objects' , 
                        type=argparse.FileType('r'), 
                        help="The network objects (e.g. zones) file",
                        )
    parser.add_argument('filterrules' , 
                        type=argparse.FileType('r'),
                        help="The filter table rules file",
                        )
    parser.add_argument('-nr','--natrules' , 
                        type=argparse.FileType('r'),
                        help="The NAT table rules file",
                        )
    parser.add_argument('-ch','--customhead',
                        type=argparse.FileType('r'),
                        help="Commands to be added on the head of the output (file)"
                        )
    parser.add_argument('-cb','--custombody',
                        type=argparse.FileType('r'),
                        help="Commands to be added on the body of the output (file)"
                        )
    parser.add_argument('-ct','--customtail',
                        type=argparse.FileType('r'),
                        help="Commands to be added on the tail of the output (file)"
                        )
    
    args = parser.parse_args(argv)
    
    config = json.load(args.config)
    objects = json.load(args.objects)
    filterrules = json.load(args.filterrules)
    if args.natrules is not None:
        natrules = json.load(args.natrules)
    else:
        natrules = []
    if args.customhead is not None:
        customhead = args.customhead.read()
    else:
        customhead = ""
    if args.custombody is not None:
        custombody = args.custombody.read()
    else:
        custombody = ""
    if args.customtail is not None:
        customtail = args.customtail.read()
    else:
        customtail = ""
    
    
    return (config,objects,filterrules,natrules,customhead,custombody,customtail)
    
class IptablesGenerator:
    def __init__(self,config,objects,filterrules,natrules,customhead,custombody,customtail):
        #self.config = config
        self.objects = objects
        self.filterrules = filterrules
        self.natrules = natrules
        
        self.customhead = customhead
        self.custombody = custombody
        self.customtail = customtail
        
        if "forwarding" in config:
            if type(config['forwarding']) is bool:
                self.forwarding = config["forwarding"]
            else:
                raise Exception("Forwarding config must be a bool")
        else:
            self.forwarding = False
    
    def __resolve_object(self,name, arg):
        """
        name is a object name (possibly all or a ! object) and arg 
        something like '-s' or '-d'
        
        """
        negate = name[0] == '!'
        name = name.lstrip('! ')
        
        arg = arg.strip()
        if negate:
            arg = " ! "+arg+" "
        else:
            arg = " "+arg+" "
        
        if name == 'all':
            if negate:
                raise Exception("Negating all zone is NOT supported")
            else:
                networks4 = [""]
                networks6 = [""]
        else:
            if name not in self.objects:
                raise Exception("object "+name+" not in know objects")
            else:
                networks4 = []
                networks6 = []
                for network in self.objects[name]["networks4"]:
                    networks4.append(arg+network)
                for network in self.objects[name]["networks6"]:
                    networks6.append(arg+network)
        if negate and (len(networks4) > 1 or len(networks6) > 1):
            raise Exception("Negation of an objects with more that one network is NOT supported")
        return ( networks4 , networks6 )
    
    def __resolve_interface(self,name, arg):
        """
        name is a object name (possibly all or a ! object) and arg 
        something like '-i' or '-o'
        
        """
        negate = name[0] == '!'
        name = name.lstrip('! ')
        
        arg = arg.strip()
        if negate:
            arg = " ! "+arg+" "
        else:
            arg = " "+arg+" "
        
        return arg + name
    
    def generate_head(self):
        self.head = ""
        if self.forwarding:
            self.head += 'echo "1" > /proc/sys/net/ipv4/ip_forward\n'
        else:
            self.head += 'echo "0" > /proc/sys/net/ipv4/ip_forward\n'
        self.head += """
modprobe ip_tables
modprobe ip_conntrack
#modprobe iptable_nat
"""
        self.head +="""
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

ip6tables -F
ip6tables -X
ip6tables -t nat -F
ip6tables -t nat -X
ip6tables -t mangle -F
ip6tables -t mangle -X

iptables -N LOGDROP
iptables -A LOGDROP -j LOG --log-prefix "iptables filter LOGDROP " --log-level 4 --log-ip-options --log-tcp-options
iptables -A LOGDROP -j DROP

ip6tables -N LOGDROP
ip6tables -A LOGDROP -j LOG --log-prefix "iptables filter LOGDROP " --log-level 4 --log-ip-options --log-tcp-options
ip6tables -A LOGDROP -j DROP

iptables -N LOGREJECT
iptables -A LOGREJECT -j LOG --log-prefix "iptables filter LOGREJECT " --log-level 4 --log-ip-options --log-tcp-options
iptables -A LOGREJECT -j REJECT       

ip6tables -N LOGREJECT
ip6tables -A LOGREJECT -j LOG --log-prefix "iptables filter LOGREJECT " --log-level 4 --log-ip-options --log-tcp-options
ip6tables -A LOGREJECT -j REJECT       

iptables -N LOGACCEPT
iptables -A LOGACCEPT -j LOG --log-prefix "iptables filter LOGACCEPT " --log-level 4 --log-ip-options --log-tcp-options
iptables -A LOGACCEPT -j ACCEPT

ip6tables -N LOGACCEPT
ip6tables -A LOGACCEPT -j LOG --log-prefix "iptables filter LOGACCEPT " --log-level 4 --log-ip-options --log-tcp-options
ip6tables -A LOGACCEPT -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
#iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
#iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -m conntrack --ctstate INVALID -j LOGDROP
ip6tables -A INPUT -m conntrack --ctstate INVALID -j LOGDROP

iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

"""
        self.head += self.customhead
        return self.head
    
    def generate_tail(self):
        self.tail = ""
        self.tail+="""
ip6tables -A INPUT -d ff00::/8 -j DROP

iptables -P OUTPUT ACCEPT
iptables -A INPUT -j LOGDROP
iptables -P INPUT DROP
iptables -A FORWARD -j LOGDROP
iptables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT
ip6tables -A INPUT -j LOGDROP
ip6tables -P INPUT DROP
ip6tables -A FORWARD -j LOGDROP
ip6tables -P FORWARD DROP

"""
        self.tail+= self.customtail
        return self.tail
    
    def generate_filterinput(self):
        self.filterinputchain = ""
        if 'input' in self.filterrules:
            for rule in self.filterrules['input']:
                if 'source' in rule:
                    ( sources4 , sources6 ) = self.__resolve_object(rule['source'],'-s')
                else:
                    ( sources4 , sources6 ) = self.__resolve_object('all','-s')

                if 'destination' in rule:
                    ( destinations4 , destinations6 ) = self.__resolve_object(rule['destination'],'-d')
                else:
                    ( destinations4 , destinations6 ) = self.__resolve_object('all','-d')
                

                if 'iface' in rule:
                    iface = self.__resolve_interface(rule['iface'],'-i')
                else:
                    iface = ""
                
                rulefilter = ""
                if 'protocol' in rule:
                    rulefilter+=" -p "+rule['protocol']
                if 'dport' in rule:
                    rulefilter+=" --dport "+str(rule['dport'])
                if 'sport' in rule:
                    rulefilter+=" --sport "+str(rule['sport'])
                if 'cstate' in rule:
                    rulefilter+=" -m conntrack --cstate "+rule['cstate']
                if 'custom' in rule:
                    rulefilter+=" "+rule['custom']
                
                for source4 in sources4:
                    for destination4 in destinations4:
                        self.filterinputchain += "iptables -A INPUT"+iface+source4+destination4+rulefilter+" -j "+rule['target']+"\n"
                for source6 in sources6:
                    for destination6 in destinations6:
                        self.filterinputchain += "ip6tables -A INPUT"+iface+source6+destination6+rulefilter+" -j "+rule['target']+"\n"
        return self.filterinputchain
    
    def generate_filteroutput(self):
        self.filteroutputchain = ""
        if 'output' in self.filterrules:
            for rule in self.filterrules['output']:
                if 'destination' in rule:
                    ( destinations4 , destinations6 ) = self.__resolve_object(rule['destination'],'-d')
                else:
                    ( destinations4 , destinations6 ) = self.__resolve_object('all','-d')
                
                if 'oface' in rule:
                    oface = self.__resolve_interface(rule['oface'],'-o')
                else:
                    oface = ""                
                
                rulefilter = ""
                if 'protocol' in rule:
                    rulefilter+=" -p "+rule['protocol']
                if 'dport' in rule:
                    rulefilter+=" --dport "+str(rule['dport'])
                if 'sport' in rule:
                    rulefilter+=" --sport "+str(rule['sport'])
                if 'cstate' in rule:
                    rulefilter+=" -m conntrack --cstate "+rule['cstate']
                if 'custom' in rule:
                    rulefilter+=" "+custom 
                
                
                for destination4 in destinations4:
                    self.filteroutputchain += "iptables -A OUTPUT"+oface+destination4+rulefilter+" -j "+rule['target']+"\n"
                for destination6 in destinations6:
                    self.filteroutputchain += "ip6tables -A OUTPUT"+oface+destination6+rulefilter+" -j "+rule['target']+"\n"
        return self.filteroutputchain

    def generate_filterforward(self):
        self.filterforwardchain = ""
        if 'forward' in self.filterrules:
            for rule in self.filterrules['forward']:
                if 'source' in rule:
                    ( sources4 , sources6 ) = self.__resolve_object(rule['source'],'-s')
                else:
                    ( sources4 , sources6 ) = self.__resolve_object('all','-s')
                if 'destination' in rule:
                    ( destinations4 , destinations6 ) = self.__resolve_object(rule['destination'],'-d')
                else:
                    ( destinations4 , destinations6 ) = self.__resolve_object('all','-d')
                
                if 'iface' in rule:
                    iface = self.__resolve_interface(rule['iface'],'-i')
                else:
                    iface = ""
                if 'oface' in rule:
                    oface = self.__resolve_interface(rule['oface'],'-o')
                else:
                    oface = ""                
                
                rulefilter = ""
                if 'protocol' in rule:
                    rulefilter+=" -p "+rule['protocol']
                if 'dport' in rule:
                    rulefilter+=" --dport "+str(rule['dport'])
                if 'sport' in rule:
                    rulefilter+=" --sport "+str(rule['sport'])
                if 'cstate' in rule:
                    rulefilter+=" -m conntrack --cstate "+rule['cstate']
                if 'custom' in rule:
                    rulefilter+=" "+custom 
                
                for source4 in sources4:
                    for destination4 in destinations4:
                        self.filterforwardchain += "iptables -A FORWARD"+source4+destination4+rulefilter+" -j "+rule['target']+"\n"
                for source6 in sources6:
                    for destination6 in destinations6:
                        self.filterforwardchain += "ip6tables -A FORWARD"+source6+destination6+rulefilter+" -j "+rule['target']+"\n"
        return self.filterforwardchain
    
    def generate_nat(self):
        self.nattable = ""
        for rule in self.natrules:
            if 'source' in rule:
                ( sources4 , sources6 ) = self.__resolve_object(rule['source'],'-s')
            else:
                ( sources4 , sources6 ) = self.__resolve_object('all','-s')
            if 'destination' in rule:
                ( destinations4 , destinations6 ) = self.__resolve_object(rule['destination'],'-d')
            else:
                ( destinations4 , destinations6 ) = self.__resolve_object('all','-d')
            
            if 'iface' in rule:
                iface = self.__resolve_interface(rule['iface'],'-i')
            else:
                iface = ""
            if 'oface' in rule:
                oface = self.__resolve_interface(rule['oface'],'-o')
            else:
                oface = ""                
            
            rulefilter = ""
            if 'protocol' in rule:
                rulefilter+=" -p "+rule['protocol']
            if 'dport' in rule:
                rulefilter+=" --dport "+str(rule['dport'])
            if 'sport' in rule:
                rulefilter+=" --sport "+str(rule['sport'])
            if 'cstate' in rule:
                rulefilter+=" -m conntrack --cstate "+rule['cstate']
            if 'custom' in rule:
                rulefilter+=" "+custom 
            if 'to4' in rule:
                to4 = " --to "+rule['to4']
            else:
                to4 = ""
            if 'to6' in rule:
                to6 = " --to "+rule['to6']
            else:
                to6 = ""
            
            for source4 in sources4:
                for destination4 in destinations4:
                    self.nattable += "iptables -t nat -A "+rule['chain']+source4+destination4+rulefilter+" -j "+rule['target']+to4+"\n"
            for source6 in sources6:
                for destination6 in destinations6:
                    self.nattable += "ip6tables -t nat -A "+rule['chain']+source6+destination6+rulefilter+" -j "+rule['target']+to6+"\n"
        return self.nattable 


    
    def generate(self):
        self.generate_head()
        self.generate_filterinput()
        self.generate_filteroutput()
        self.generate_filterforward()
        self.generate_nat()
        self.generate_tail()
        self.output = ""
        self.output += self.head + "\n"
        self.output += self.filterinputchain + "\n" 
        self.output += self.filteroutputchain + "\n" 
        self.output += self.filterforwardchain + "\n" 
        self.output += self.nattable + "\n" 
        self.output += self.custombody + "\n"
        self.output += self.tail + "\n"
        return self.output






def main():
    ( config, objects, filterrules, natrules, customhead, custombody, customtail ) = argparser()
    generator = IptablesGenerator(config, objects, filterrules, natrules,customhead,custombody,customtail)
    print(generator.generate())
    
    
if __name__ == "__main__":
    main()
