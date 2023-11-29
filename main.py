from tabulate import tabulate
import subprocess as sp
import time
import os

def printBanner():
    bannerTxt = '''  _________                     _____  ________                       .___._.
 /   _____/_____   ____   _____/ ____\\/  _____/ __ _______ _______  __| _/| |
 \\_____  \\\\____ \\ /  _ \\ /  _ \\   __\\/   \\  ___|  |  \\__  \\\\_  __ \\/ __ | | |
 /        \\  |_> >  <_> |  <_> )  |  \\    \\_\\  \\  |  // __ \\|  | \\/ /_/ |  \\|
/_______  /   __/ \\____/ \\____/|__|   \\______  /____/(____  /__|  \\____ |  __
        \\/|__|                               \\/           \\/           \\/  \\/'''
    print(bannerTxt)
    print('============================================================================')
    print('Welcome to SpoofGuard! Here to detect if any ARP spoof attack is ongoing on your device.')
    print('Detecting interfaces on your device...\n')
    
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=checkPacket)

def checkPacket(pkt):
    if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
        time.sleep(3)
        checkARPtable()

def getInterfaces():
    interfaceDict = {}
    cmd = "netsh interface ipv4 show interfaces"
    interface_pro = sp.Popen(cmd,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,text=True)
    output,error = interface_pro.communicate()
    if interface_pro.returncode!=0:
        return {"status":False,"error":error}
    else:
        arr = []
        flag1 = False
        output = output.split('\n')
        for i in output:
            if i=="":
                flag1 = False
            if flag1:
                k = i.split(' ')
                l = []
                for j in k:
                    if j!="":
                        l.append(j)
                arr.append(l)
            if i.find('Loopback')!=-1:
                flag1 = True
        for j in arr:
            flag2 = False
            for l in j:
                if l=='disconnected':
                    flag2 = True
            if not flag2:
                m = ""
                for i in range(4,len(j)):
                    m = m+j[i]+" "
                interfaceDict[m.strip()] = int(j[0])
    return {"status":True,"interfaceList":interfaceDict}

def checkARPtable(Idx,userInterface):
    cmd = "arp -a"
    arp_process = sp.Popen(cmd,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,text=True)
    output,error = arp_process.communicate()
    if arp_process.returncode != 0:
        print("Error fetching arp table: ",error)
        os._exit(1)

    li = output.split('\n')
    li = li[1:-1]
    dynamicMACsFull = []
    
    for x in Idx:
        index = hex(x)[1::]
        dynamicMACs = []
        printit = False
        for i in li:
            if i=="":
                continue
            if i.find('Interface')!=-1:
                if i.find(index)!=-1:
                    printit=True
                else:
                    printit=False
            else:
                if printit:
                    if i.find('dynamic')!=-1:
                        dynamicMACs.append(i)
        for i in range(len(dynamicMACs)):
            q = dynamicMACs[i].split(' ')
            e = []
            for j in q:
                if j!="":
                    e.append(j)
            dynamicMACs[i] = e
        dynamicMACsFull.append(dynamicMACs)
        
    for x in range(len(dynamicMACsFull)):        
        MAC_set = set()
        for i in dynamicMACsFull[x]:
            if i[1] in MAC_set:
                print('Interface:',userInterface[x],'- ALERT!! You might be under attack. Please ensure using secure protocols!')
            else:
                MAC_set.add(i[1])
        MAC_set.clear()

def getIdx():
    interfaceName = "Wi-Fi"
    cmd = "netsh interface ipv4 show interfaces"
    interface_process = sp.Popen(cmd,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,text=True)
    output,error = interface_process.communicate()
    if interface_process.returncode!=0:
        return {'status':False,"error":error}
    else:
        li = output.split('\n')[1:-1]
        for k in li:
            i = k.strip()
            if i.find(interfaceName)!=-1:
                return {"status":True,"Idx":int(i.split(' ')[0])}
        return {"status":False,"error":"no interface found by that name"}

def main():
    printBanner()
    interfaceList = getInterfaces()
    if interfaceList['status'] == False:
        print("Some error occured!")
        print(interfaceList['error'])
        os._exit(1)
    else:
        interfaceList = interfaceList['interfaceList']
        interfaceList['All interfaces'] = -1
        print(tabulate([[i,interfaceList[i]] for i in interfaceList], headers=['Interface Name', 'Idx']),'\n')
        userInput = input("Select an interface by entering the Idx: ")
        try:
            userInput = int(userInput)
        except ValueError:
            print('Idx should be integer type only!')
            os._exit(1)
        if userInput in interfaceList.values():
            userInterface = None
            if userInput == -1:
                try:
                    while True:
                        time.sleep(3)
                        print('Checking all interfaces again...')
                        checkARPtable([i for i in interfaceList.values() if i != -1],[i for i in interfaceList.keys()])
                except KeyboardInterrupt:
                    os._exit(1)
            else:
                for i in interfaceList:
                    if interfaceList[i] == userInput:
                        userInterface = i
                try:
                    while True:
                        time.sleep(3)
                        print('Checking the',userInterface,'interface again...')
                        checkARPtable([userInput],[userInterface])
                except KeyboardInterrupt:
                    os._exit(1)
        else:
            print('Incorrect idx entered! Your input:',userInput)

if __name__ == '__main__':
    main()
