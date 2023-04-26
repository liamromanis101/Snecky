#!/usr/bin/python3
#version 0.9.3a
#Author: Liam Romanis

from os import popen
from scapy.all import *
import sys
import psutil
import time
from prettytable import PrettyTable, MSWORD_FRIENDLY
import string
from markupsafe import Markup, escape
from pyfiglet import Figlet



load_contrib('ospf')
load_contrib('stp')
load_contrib('vrrp')
load_contrib('hsrp')
load_contrib('llc')
load_contrib('snmp')
load_contrib('cdp')


name = ''
f = ''
d = 0
b = 1
o = 0
v = 0
pkthex = ''
list=['']
list2=['']

#vrrp lists
listvrrpver=['']
listvrrpatype=['']
listvrrppri=['']
listvrrp=['']

#hsrp lists
listhsrpauth=['']
listhsrppri=['']

#ospf lists
listospfver=['']
listospfsrc=['']
listospfautht=['']
listospfauthd=['']

#cpha lists
listcpha=['']

#snmp lists
snmplist=['']
snmpverlist=['']

#cdp lists
cdp1src=['']
cdp2src=['']

#802.1q lists
vlantagsrc=['']

#DTP list
dtpsrc=['']

#VTP list
vtpsrc=['']

hsrp = PrettyTable(['version', 'priority', 'authentication', 'virtual ip'])
vrrp = PrettyTable(['version', 'priority', 'auth type', 'authentication', 'address list'])
ospf = PrettyTable(['version', 'auth type', 'authentication', 'src address'])
stp = PrettyTable([])
snmp = PrettyTable(['source','destination','version','community'])
cdp1 = PrettyTable(['devicename','softwareversion','platform','ipaddress', 'capabilities', 'gateway'])
cdp2 = PrettyTable(['devicename','softwareversion','platform','ipaddress', 'capabilities'])
vlantag = PrettyTable(['vlan_id','vlan_priority', 'ether_type', 'payload'])
dtp = PrettyTable(['dp_version', 'status', 'tlv_mode', 'vlan', 'auth', 'auth_type]'])
vtp = PrettyTable(['vtp_version', 'domain', 'operation', 'vlan', 'auth', 'auth_type'])

vrrp.set_style(MSWORD_FRIENDLY)
hsrp.set_style(MSWORD_FRIENDLY)
ospf.set_style(MSWORD_FRIENDLY)
snmp.set_style(MSWORD_FRIENDLY)
cdp1.set_style(MSWORD_FRIENDLY)
cdp2.set_style(MSWORD_FRIENDLY)


def interfaces():
	addrs = psutil.net_if_addrs()
	#print(addrs.keys())
	return addrs


def print_pkt2(pkt):
	a = pkt.show(dump=True)
	print(a)



def print_pkt(pkt):
	for p in pkt:
		a = p.show(dump=True)
		
		if pkt.haslayer(VTP):
			vtp_layer = pkt.getlayer(VTP)
			version = vtp_layer.version
			domain = vtp_layer.domain
			vtpsrc.append(domain)
			operation = vtp_layer.code
			vlan = vtp_layer.vlan_id
			auth = vtp_layer.auth
			auth_type = vtp_layer.auth_type
			vtp.add_row([vtp_version, domain, operation, vlan, auth, auth_type])
		
		if p.haslayer(Ether):
			ether_packet = p[Ether]
			if ether_packet.type == 0x2004:
				if p.haslayer(DTP):
					dtp_layer = pkt.getlayer(DTP)
					version = dtp_layer.version
					status = dtp_layer.status
					dtpsrc.append(status)
					tlv_mode = dtp_layer.tlv_mode
					vlan = dtp_layer.vlan
					auth = dtp_layer.auth
					auth_type = dtp_layer.auth_type
					dtp.add_row([dtp_version, status, tlv_mode, vlan, auth, auth_type])

		if p.haslayer(Dot1Q):
        		vlan_packet = packet[Dot1Q]
        		# Extract the VLAN fields
        		vlan_id = vlan_packet.vlan
        		vlantagsrc.append(vlan_id)
        		vlan_priority = vlan_packet.prio
        		ether_type = vlan_packet.type
        		payload = vlan_packet.payload
        		vlantag.add_row([vlan_id, vlan_priority, ether_type, payload])

		if (p.haslayer("Cisco Discovery Protocol version 1")):
			print("CDPv1 Found")
			cdp1name = pkt.getlayer("Device ID").val
			cdp1sysver = pkt.getlayer("Software Version").val
			cdp1plat = pkt.getlayer("Platform").val
			cdp1ip4 = pkt.getlayer("CDP Address IPv4").addr
			cdp1src.append(cdp1ip4)
			cdp1cap =  pkt.getlayer("Capabilities").cap
			cdp1gw = pkt.getlayer("IP Prefix").defaultgw
			cdp1.add_row([cdp1name, cdp1sysver, cdp1plat, cdp1ip4, cdp1cap, cdp1gw])


		if (p.haslayer("Cisco Discovery Protocol version 2")):
			print("CDPv2 Found")
			cdp2name = pkt.getlayer("Device ID").val
			cdp2sysver = pkt.getlayer("Software Version").val
			cdp2plat = pkt.getlayer("Platform").val
			cdp2ip4 = pkt.getlayer("CDP Address IPv4").addr
			cdp2src.append(cdp2ip4)
			cdp2cap =  pkt.getlayer("Capabilities").cap
			cdp2.add_row([cdp2name, cdp2sysver, cdp2plat, cdp2ip4, cdp2cap])


		if (p.haslayer(SNMP)):
			print("SNMP Found")
			ssrc = pkt.getlayer(IP).src
			snmplist.append(ssrc)
			sdst = pkt.getlayer(IP).dst
			sver = repr(pkt.getlayer(SNMP).version)
			if "0x1" in sver:
				sver1 = "2c"
				snmpverlist.append(sver)
			if "0x0" in sver:
				sver1 = "1"
				snmpverlist.append(sver)
			if "0x2" in sver:
				sver1 = "?"
				snmpverlist.append(sver)
			if "0x3" in sver:
				sver1 = "3"
				snmpverlist.append(sver)
				scomm = str(pkt.getlayer(SNMP).community)
				scomm1 = scomm.strip()
				printable = set(string.printable)
				scomm2 = filter(lambda x: x in string.printable, scomm1)
				scomm3 = escape(scomm2)
				snmp.add_row([ssrc, sdst, sver1, scomm3])


		if (p.haslayer("OSPF Header")):
			print("OSPF Found")
			versiono = pkt.getlayer("OSPF Header").version
			listospfver.append(versiono)
			srconn = pkt.getlayer("OSPF Header").src
			if not srconn in listospfsrc:
				listospfsrc.append(srconn)
				authooo = pkt.getlayer("OSPF Header").authtype
				listospfautht.append(authooo)
				authdooo = pkt.getlayer("OSPF Header").authdata
				listospfauthd.append(authdooo)
				ospf.add_row([versiono, authooo, authdooo, srconn])


		if (p.haslayer(HSRP)):
			print("HSRP found")
			versionn = pkt.getlayer(HSRP).version
			priorityn = pkt.getlayer(HSRP).priority
			if not priorityn in listhsrppri:
				authn1 = pkt.getlayer(HSRP).auth
				printable1 = set(string.printable)
				authn2 = filter(lambda x: x in printable1, authn1)
				vipna = pkt.getlayer(HSRP).virtualIP
				listhsrpauth.append(authn1)
				listhsrppri.append(priorityn)
				hsrp.add_row([versionn, priorityn, authn2, vipna])

		if (p.haslayer(VRRP)):
			print("VRRP found")
			versionv = pkt.getlayer(VRRP).version
			listvrrpver.append(versionv)
			priorityn = pkt.getlayer(VRRP).priority
			listvrrppri.append(priorityn)
			authtypen = pkt.getlayer(VRRP).authtype
			listvrrpatype.append(authtypen)
			vipn4 = pkt.getlayer(VRRP).addrlist
			vipn4 = str(vipn4)
			vipn3 = vipn4.replace('[', '')
			vipn2 = vipn3.replace(']', '')
			vipn1 = vipn2.replace("'", '')
			if not vipn1 in listvrrp:
				listvrrp.append(vipn1)
				pp = str(p)
				ppp = pp[-14:]
				ppp = ppp.strip()
				printable = set(string.printable)
				pppp = filter(lambda x: x in printable, ppp)
				if 0 == authtypen:
					pppp = "Null"
					vrrp.add_row([versionv, priorityn, authtypen, pppp, vipn1])

#		if (p.haslayer(STP)):
#			bpduflags = pkt.getlayer(STP).bpduflags
#			print "SCAPY SAYS BPDUFLAGS = ", bpduflags
#
#		if "8116" in a:
#			print "CPHA Packet Found\n"
#			pkthex = restore(hexdump(pkt))
	return


if __name__ == '__main__':


	custom_fig = Figlet(font='graffiti')
	print(custom_fig.renderText('Snecky'))
	print("A passive network protocol security tool\n")
	uid=os.getuid()
	print(uid)
	if uid==0:
		print("You are root - excellent")
	else:
		print("your are not root, this script requires root privileges")
		sys.exit(0)

	addresses = interfaces()
	print("Select which Interface you would like to sniff on:")
	print("Hint: If you have vlans configured select the base interface to sniff on all of them")
	ints = []
	#print len(ints)
	b = 0
	for i in addresses:
		print('%i : %s' % (b,i))
		ints.append(i)
		b += 1

	n = int(input("Enter a number:"))
	#print int(n)
	intf = ints[n]
	print("Will sniff on interface %s" % (intf))
	print("Please supply a maximum number of packets to collect:")
	print("0 means infinity which would be excessive!!")
	try:
		c = int(input("Enter a Number:"))
	except ValueError:
		print("That was not an integer.. Muppet!")
	if  c == 0:
		print("You really are a muppet!")
	else:
		#print c
		pkt=sniff(count=c,iface=intf,prn=print_pkt)


	#for vrrpline in range(len(vrrp)):
	#	print vrrp[vrrpline],


	if len(listhsrppri) > 1:
		print("\n\n--HSRP Results--")
		print(hsrp)

	if len(listvrrpver) > 1:
		print("\n\n--VRRP Results--")
		print(vrrp)
	if len(listospfver) > 1:
		print("\n\n--OSPF Results--")
		print(ospf)
	if len(snmplist) > 1:
		print("\n\n--SNMP Results--")
		print(snmp)

	if len(cdp1src) > 1:
		print("\n\n\--CDP v1 Results--")
		print(cdp1)

	if len(cdp2src) > 1:
		print("\n\n\--CDP v2 Results--")
		print(cdp2)
		
	if len(vlantagsrc) > 1:
		print("\n\n--801.1Q Results--")
		print(vlantag)
		
	if len(dtpsrc) > 1:
		print("\n\n--DTP Results--")
		print(dtp)
		
	if len(vtpsrc) > 1:
		print('--VTP Results--')
		print(vtp)


 
