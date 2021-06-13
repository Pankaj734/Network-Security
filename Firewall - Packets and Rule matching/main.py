import ipaddress
import time
import sys

class Rules :
    num = []
    s_ip = []
    d_ip = []
    s_port = []
    d_port = []
    protocol = []
    data = []

    def add(self,num, sip, dip, sport, dport, p, d) :
        self.num.append(num.strip())
        self.s_ip.append(sip.strip())
        self.d_ip.append(dip.strip())
        self.s_port.append(sport.strip())
        self.d_port.append(dport.strip()) 
        self.protocol.append(p.strip())
        self.data.append(d.strip()) 

    def print(self) :
        print(self.s_ip)
        print(self.d_ip)
        print(self.s_port)
        print(self.d_port)
        print(self.protocol)
        print(self.data)

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

def get_addr_network(address, net_size):
    #Convert ip address to 32 bit binary
    ip_bin = ip_to_binary(address)
    #Extract Network ID from 32 binary
    network = ip_bin[0:32-(32-net_size)]    
    return network

def ip_in_prefix(ip_address, prefix):
    #CIDR based separation of address and network size
    [prefix_address, net_size] = prefix.split("/")
    #Convert string to int
    net_size = int(net_size)
    #Get the network ID of both prefix and ip based net size
    prefix_network = get_addr_network(prefix_address, net_size)
    ip_network = get_addr_network(ip_address, net_size)
    return ip_network == prefix_network


# function to match the packet with the rules
def match(s_ip,d_ip,s_p,d_p,p,d) :
    RuleLen = int(len(obj.num))
    res = ""
    matchList = []

    for i in range(0,RuleLen) :
        count = 0        

        #source ip match
        if obj.s_ip[i] == "0.0.0.0/0" :
            count = count + 1
        else :
            if ip_in_prefix(s_ip, obj.s_ip[i]):
                count = count + 1
        
        #destination ip match
        if obj.d_ip[i].strip() == "0.0.0.0/0" :
            count = count + 1
        else :
            if ip_in_prefix(d_ip, obj.d_ip[i]):
                count = count + 1
        
        #source port match
        if obj.s_port[i].strip() == "0" :
            count = count + 1
        elif obj.s_port[i] == s_p :
            count = count + 1
        else :
            rng = obj.s_port[i].split("-")
            if int(s_p) in range( int(rng[0]) , int(rng[1])+1) :
                count = count + 1

        #desttination port match
        if obj.d_port[i].strip() == "0" :
            count = count + 1
        elif obj.d_port[i] == d_p :
            count = count + 1
        else :
            rng = obj.d_port[i].split("-")
            if int(d_p) in range( int(rng[0]) , int(rng[1])+1) :
                count = count + 1
        
        #protocol match
        if obj.protocol[i] == p :
            count = count + 1
        
        #data match 
        if obj.data[i].strip() in d :
            count = count + 1
        
        if count == 6 : #if all parameters matches
            matchList.append(obj.num[i])
    
    listlen = int(len(matchList))
    if listlen:
        for i in range(0,listlen) :
            res += matchList[i]
            res += " "
    else :
        res = "no rule"
    
    return res

rf = sys.argv[1]
pf = sys.argv[2]

f = open(rf,"r")
num = ""
s_ip = ""
d_ip = ""
s_p = ""
d_p = ""
protocol = ""
data = ""

obj = Rules()
invalid = 0
RuleCount = 0
validRules = 0
for line in f:
    if line.strip("\n") == "BEGIN" :
        continue
    if line.strip("\n") == "END":
        RuleCount = RuleCount + 1
        if invalid == 0 :
            obj.add(num,s_ip,d_ip,s_p,d_p,protocol,data)
            validRules = validRules + 1
        invalid = 0
        continue
    
    parts = line.strip("\n").split(":")
    if parts[0] == "NUM" :
        num = parts[1]
        continue
    
    if parts[0] == "SRC IP ADDR" :
        s_ip = parts[1]
        continue
    elif parts[0] == "DEST IP ADDR" :
        d_ip = parts[1]
        continue
        
    elif parts[0] == "SRC PORT" :
        rng = parts[1].split("-")
        if int(rng[0]) == int(rng[1]) and int(rng[0]) == 0 :
            s_p = rng[0]
            continue
        elif int(rng[0]) in range(1,65536) :
            if int(rng[1]) in range(1,65536) :
                if int(rng[0]) == int(rng[1]) :
                    s_p = rng[0]
                    continue
                elif int(rng[0]) < int(rng[1]) :
                    s_p = parts[1]
                    continue
                else :
                    invalid = 1
                    continue
            else :
                invalid = 1
                continue
        else :
            invalid = 1
            continue
        
    elif parts[0] == "DEST PORT" and invalid == 0:
        rng = parts[1].split("-")
        if int(rng[0]) == int(rng[1]) and int(rng[0]) == 0 :
            d_p = rng[0]
            continue
        elif int(rng[0]) in range(1,65536) :
            if int(rng[1]) in range(1,65536) :
                if int(rng[0]) == int(rng[1]) :
                    d_p = rng[0]
                    continue
                elif int(rng[0]) < int(rng[1]) :
                    d_p = parts[1]
                    continue
                else :
                    invalid = 1
                    continue
            else :
                invalid = 1
                continue
        else :
            invalid = 1
            continue

    elif parts[0] == "PROTOCOL" and invalid == 0:
        protocol = parts[1]
        continue
    
    elif parts[0] == "DATA" and invalid == 0:
        data = parts[1]
        continue
    
f.close()

print(f"A total of {RuleCount} rules were read; {validRules} valid rules are stored.")


f = open(pf,"r")
num = ""
s_ip = ""
d_ip = ""
s_p = ""
d_p = ""
protocol = ""
data = ""

invalid = 0
PktCnt = 0
totalpkt = 0
total = 0
for line in f:
    if line.strip("\n") == "BEGIN" :
        continue
    if line.strip("\n") == "END":
        totalpkt = totalpkt + 1
        if invalid == 0 :
            PktCnt = PktCnt + 1

            #timer start
            start = time.time()
            res = match(s_ip.strip(), d_ip.strip(), s_p.strip(), d_p.strip(), protocol.strip(), data.strip())
            end = time.time()
            #timer ends

            total = total + (end-start)
            if res == "no rule" :
                print(f"Packet number {num.strip()} matches {res.strip()}.")
            else :
                print(f"Packet number {num.strip()} matches rule(s): {res.strip()}.")
        else :
            print(f"Packet number {num.strip()} is Invalid.")
        invalid = 0
        continue
    
    parts = line.strip("\n").split(":")

    if parts[0] == "NUM" :
        num = parts[1]
        continue
    
    if parts[0] == "SRC IP ADDR" :
        s_ip = parts[1]
        continue
    elif parts[0] == "DEST IP ADDR" :
        d_ip = parts[1]
        continue
        
    elif parts[0] == "SRC PORT" :
        port = int(parts[1])
        if port in range(0,65536) :
            s_p = parts[1]
            continue
        else :
            invalid = 1
            continue
        
    elif parts[0] == "DEST PORT" and invalid == 0:
        port = int(parts[1])
        if port in range(0,65536) :
            d_p = parts[1]
            continue
        else :
            invalid = 1
            continue 

    elif parts[0] == "PROTOCOL" and invalid == 0:
        protocol = parts[1]
        continue
    elif parts[0] == "DATA" and invalid == 0:
        data = parts[1]
        continue

f.close()

print(f"A total of {totalpkt} packet(s) were read from the file and {PktCnt} valid packet(s) processed. Bye.")
print(f"Average time taken per packet: {total/PktCnt} seconds.")