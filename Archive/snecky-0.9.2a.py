#!/usr/bin/python3

from os import popen
from scapy.all import *
import sys
import psutil
import time
from prettytable import PrettyTable, MSWORD_FRIENDLY
import string
from markupsafe import Markup, escape



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

hsrp = PrettyTable(['version', 'priority', 'authentication', 'virtual ip'])
vrrp = PrettyTable(['version', 'priority', 'auth type', 'authentication', 'address list'])
ospf = PrettyTable(['version', 'auth type', 'authentication', 'src address'])
stp = PrettyTable([])
snmp = PrettyTable(['source','destination','version','community'])
cdp1 = PrettyTable(['devicename','softwareversion','platform','ipaddress', 'capabilities', 'gateway'])
cdp2 = PrettyTable(['devicename','softwareversion','platform','ipaddress', 'capabilities'])


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

	uid=os.getuid()
	print(uid)
	if uid==0:
		print("You are root - excellent")
	else:
		print("your are not root, this script requires root privileges")
		sys.exit(0)

	print("Enter the name you would like for the report")
	name = str(input("Enter Report Name: "))
	repname = name + ".nessus"
	f = open(repname, "a+")
	f.write('<?xml version="1.0" ?>\n')
	f.write('<NessusClientData_v2>\n')
	f.write('<Policy><policyName>MyPolicy</policyName>\n')
	f.write('</Policy>\n')
	f.write('<Preferences>\n')
	f.write('<preference><name>TARGET</name>\n')
	f.write('<value>Change Me</value>\n')
	f.write('</preference>\n')
	f.write('</Preferences>\n')
	report_name = '<Report name="'
	report_name = report_name + repname 
	report_name = report_name + '" xmlns:cm="http://www.nessus.org/cm">\n'
	f.write(report_name)
	f.write('\n')


	print("Enter the name of the Job, VLAN or Environment you are assessing.")
	netname = input("Enter a Name: ")
	netname1 = '<ReportHost name="'
	netname1 = netname1 + netname
	netname1 = netname1 + '">'
	f.write(netname1)
	f.write('\n')
	f.write('<HostProperties>\n')
	f.write('</HostProperties>\n')

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
		pkt=sniff(count=c,iface=intf,prn=print_pkt2)


	#for vrrpline in range(len(vrrp)):
	#	print vrrp[vrrpline],

	if len(listhsrppri) > 1:
		if "255" in listhsrppri:
			f.write('<ReportItem port="1985" svc_name="hsrp" protocol="udp" severity="2" pluginID="99999" pluginName="HSRP Weaknesses" pluginFamily="Misc.">\n')
			f.write('<cvss3_base_score>5.8</cvss3_base_score>\n')
			f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
			f.write('<cvss_base_score>5.5</cvss_base_score>\n')
			f.write('<cvss_vector>CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C</cvss_vector>\n')
			f.write('<description>HSRP (Hot Standy Router Protocol) Packets were captured. HSRP is used to provide a fault tolerant gateway.\n')
			f.write('The security of this protocol is provided by the selection of Priority (0 - 255) and the authentication used.\n')
			f.write('In this case a master device with a priority of 255 was found which dramatically reduces the risk of MitM (Man in the Middle) attacks. However, the risk of denial of service is still a risk\n')
			if "NONE" in listhsrpauth:
				f.write('Some packets were found with no authentication configured which may increase the risk of denial of service attacks being successful.\n')
				f.write('</description>\n')
				f.write('<fname>hsrp.nasl</fname>\n')
				f.write('<plugin_modification_date>2019/11/14</plugin_modification_date>\n')
				f.write('<plugin_name>HSRP Passive Analysis</plugin_name>\n')
				f.write('<plugin_publication_date>2019/11/14</plugin_publication_date>\n')
				f.write('<plugin_type>Passive</plugin_type>\n')
				f.write('<risk_factor>Medium</risk_factor>\n')
				f.write('<script_version>0.1</script_version>\n')
				f.write('<see_also>https://isc.sans.edu/formums/diary/Network+Reliability+Part+2+HSRP+Attacks+and+Defenses/10120/</see_also>\n')
				f.write('<solution>InteliSecure recommends that MD5 Authentication is configured.</solution>\n')
				hsrptab = hsrp.get_string()
				f.write(hsrptab)
				f.write('</plugin_output>\n')
				f.write('</ReportItem>')
		else:
			f.write('<ReportItem port="1985" svc_name="hsrp" protocol="udp" severity="3" pluginID="99999" pluginName="HSRP Weaknesses" pluginFamily="Misc.">\n')
			f.write('<cvss3_base_score>5.8</cvss3_base_score>\n')
			f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
			f.write('<cvss_base_score>7.7</cvss_base_score>\n')
			f.write('<cvss_vector>CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C</cvss_vector>\n')
			f.write('<description>HSRP (Hot Standy Router Protocol) Packets were captured.  HSRP is used to provide a fault tolerant gateway.\n')
			f.write('The security of this protocol is provided by the selection of Priority (0 - 255) and the authentication used.\n')
			f.write('In this case a master device with a priority of 255 was not found which dramatically increases the risk of MitM (Man in the Middle) attacks and denial of service.\n')
			if "NONE" in listhsrpauth:
				f.write('Some packets were found with no authentication configured which may increase the risk of MitM and denial of service attacks being successful.\n')
				f.write('</description>\n')
				f.write('<fname>hsrp.nasl</fname>\n')
				f.write('<plugin_modification_date>2019/11/14</plugin_modification_date>\n')
				f.write('<plugin_name>HSRP Passive Analysis</plugin_name>\n')
				f.write('<plugin_publication_date>2019/11/14</plugin_publication_date>\n')
				f.write('<plugin_type>Passive</plugin_type>\n')
				f.write('<risk_factor>High</risk_factor>\n')
				f.write('<script_version>0.1</script_version>\n')
				f.write('<see_also>https://isc.sans.edu/formums/diary/Network+Reliability+Part+2+HSRP+Attacks+and+Defenses/10120/</see_also>\n')
				f.write('<solution>InteliSecure recommends that the Master device is configured with a priority of 255 and that MD5 Authentication is configured.</solution>\n')
				f.write('<plugin_output>\n')
				hsrptab = hsrp.get_string()
				f.write(hsrptab)
				f.write('</plugin_output>\n')
				f.write('</ReportItem>\n')

		print("\n\n")
	if len(listvrrpatype) > 1:
		if "255" in listvrrppri:
			f.write('<ReportItem port="112" svc_name="vrrp" protocol="udp" severity="2" pluginID="99998" pluginName="VRRP Weaknesses" pluginFamily="Misc.">\n')
			f.write('<cvss3_base_score>5.8</cvss3_base_score>\n')
			f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
			f.write('<cvss_base_score>5.5</cvss_base_score>\n')
			f.write('<cvss_vector>CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C</cvss_vector>\n')
			f.write('<description>VRRP (Virtual Router Router Protocol) Packets were captured. VRRP is used to provide a fault tolerant gateway.\n')
			f.write('The security of this protocol is provided by the selection of Priority (0 - 255) and the authentication used.\n')
			f.write('In this case a master device with a priority of 255 was found which dramatically reduces the risk of MitM (Man in the Middle) attacks. However, the risk of denial of servic')
			if "0" in listvrrpatype:
				f.write('VRRP packets were found which had no authenticaton configured. This is poor practice and could increase the risk of denial of service attacks.')
			if "1" in listvrrpatype:
				f.write('VRRP packets weee found which had plain text authentication configured. This type of authentication is vulnerable to snooping.')
				f.write('Once a threat actor has the authentication text he could launch denial of service attacks. ')
				f.write('</description>\n')
				f.write('<fname>vrrp.nasl</fname>\n')
				f.write('<plugin_modification_date>2019/11/14</plugin_modification_date>\n')
				f.write('<plugin_name>VRRP Passive Analysis</plugin_name>\n')
				f.write('<plugin_publication_date>2019/11/14</plugin_publication_date>\n')
				f.write('<plugin_type>Passive</plugin_type>\n')
				f.write('<risk_factor>Medium</risk_factor>\n')
				f.write('<script_version>0.1</script_version>\n')
				f.write('<see_also></see_also>\n')
				f.write('<solution>InteliSecure recommends that MD5 Authentication is configured.</solution>\n')
				f.write('<plugin_output>\n')
				vrrptab = vrrp.get_string()
				f.write(vrrptab)
				f.write('</plugin_output>\n')
				f.write('</ReportItem>\n')
		else:
			f.write('<ReportItem port="112" svc_name="vrrp" protocol="udp" severity="3" pluginID="99998" pluginName="VRRP Weaknesses" pluginFamily="Misc.">\n')
			f.write('<cvss3_base_score>5.8</cvss3_base_score>\n')
			f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
			f.write('<cvss_base_score>7.7</cvss_base_score>\n')
			f.write('<cvss_vector>CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C</cvss_vector>\n')
			f.write('<description>VRRP (Virtual Router Router Protocol) Packets were captured. VRRP is used to provide a fault tolerant gateway.\n')
			f.write('The security of this protocol is provided by the selection of Priority (0 - 255) and the authentication used.\n')
			f.write('In this case a master device with a priority of 255 was not found which dramatically increases the risk of MitM (Man in the Middle) attacks and denial of service. ')
			if "0" in listvrrpatype:
				f.write('VRRP packets were found which had no authenticaton configured. This is poor practice and could increase the risk of denial of service attacks.')
			if "1" in listvrrpatype:
				f.write('VRRP packets weee found which had plain text authentication configured. This type of authentication is vulnerable to snooping.')
				f.write('Once a threat actor has the authentication text he could launch denial of service attacks. ')
				f.write('</description>\n')
				f.write('<fname>vrrp.nasl</fname>\n')
				f.write('<plugin_modification_date>2019/11/14</plugin_modification_date>\n')
				f.write('<plugin_name>VRRP Passive Analysis</plugin_name>\n')
				f.write('<plugin_publication_date>2019/11/14</plugin_publication_date>\n')
				f.write('<plugin_type>Passive</plugin_type>\n')
				f.write('<risk_factor>Medium</risk_factor>\n')
				f.write('<script_version>0.1</script_version>\n')
				f.write('<see_also></see_also>\n')
				f.write('<solution>InteliSecure recommends that MD5 Authentication is configured and that the Master device is configured with a priority of 255.</solution>\n')
				f.write('<plugin_output>\n')
				vrrptab = vrrp.get_string()
				f.write(vrrptab)
				f.write('</plugin_output>\n')
				f.write('</ReportItem>\n')

if len(listospfver) > 1:
	#print len(listospfver)
	#print listospfautht
	if 0 in listospfautht:
		f.write('<ReportItem port="89" svc_name="ospf" protocol="udp" severity="3" pluginID="99997" pluginName="OSPF Weaknesses" pluginFamily="Misc.">\n')
		f.write('<cvss3_base_score>7.7</cvss3_base_score>\n')
		f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
		f.write('<cvss_base_score>9.0</cvss_base_score>\n')
		f.write('<cvss_vector>CVSS2#(AV:N/AC:L/Au:N/C:P/I:P/A:C)</cvss_vector>\n')
		f.write('<description>OSPF (Open Shortest Path First) Packets were captured. OSPF is used to distribute IP routing information throughout an Autonomous System (AS) in a network.\n')
		f.write('The security of this protocol is provided by the authentication used.\n')
		f.write('In this case an Athentication Type of Null was configured, meaning that no authentication is configured. This will increase the risk of successful remote attacks against OSPF as the Authentication Data does not need to be known.\n ')
		f.write('Man in the Middle (MitM), Denial of Service and potentially, malicious route insertion could occur.\n')
		f.write('</description>\n')
		f.write('<fname>ospf.nasl</fname>\n')
		f.write('<plugin_modification_date>2019/11/14</plugin_modification_date>\n')
		f.write('<plugin_name>OSPF Passive Analysis</plugin_name>\n')
		f.write('<plugin_publication_date>2019/11/14</plugin_publication_date>\n')
		f.write('<plugin_type>Passive</plugin_type>\n')
		f.write('<risk_factor>High</risk_factor>\n')
		f.write('<script_version>0.1</script_version>\n')
		f.write('<solution>InteliSecure recommends that MD5 Authentication is configured.</solution>\n')
		f.write('<plugin_output>\n')
		ospftab = ospf.get_string()
		f.write(ospftab)
		f.write('</plugin_output>\n')
		f.write('</ReportItem>\n')
		if 1 in listospfautht:
			f.write('<ReportItem port="89" svc_name="ospf" protocol="udp" severity="3" pluginID="99997" pluginName="OSPF Weaknesses" pluginFamily="Misc.">\n')
			f.write('<cvss3_base_score>7.3</cvss3_base_score>\n')
			f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
			f.write('<cvss_base_score>7.0</cvss_base_score>\n')
			f.write('<cvss_vector>CVSS2#AV:(AV:A/AC:L/Au:N/C:P/I:P/A:C)</cvss_vector>\n')
			f.write('<description>OSPF (Open Shortest Path First) Packets were captured. OSPF is used to distribute IP routing information throughout an Autonomous System (AS) in a network.\n')
			f.write('The security of this protocol is provided by the authentication used.\n')
			f.write('In this case an Athentication Type of Simple was configured, meaning that Plain Text authentication is configured. This will increase the risk of successful attacks on the local LAN')
			f.write('Man in the Middle (MitM), Denial of Service and potentially, malicious route insertion could occur.\n')
			f.write('</description>\n')
			f.write('<fname>ospf.nasl</fname>\n')
			f.write('<plugin_modification_date>2019/11/14</plugin_modification_date>\n')
			f.write('<plugin_name>OSPF Passive Analysis</plugin_name>\n')
			f.write('<plugin_publication_date>2019/11/14</plugin_publication_date>\n')
			f.write('<plugin_type>Passive</plugin_type>\n')
			f.write('<risk_factor>High</risk_factor>\n')
			f.write('<script_version>0.1</script_version>\n')
			f.write('<solution>InteliSecure recommends that MD5 Authentication is configured.</solution>\n')
			f.write('<plugin_output>\n')
			ospftab = ospf.get_string()
			f.write(ospftab)
			f.write('</plugin_output>\n')
			f.write('</ReportItem>\n')
			if len(snmplist) > 1:
				f.write('<ReportItem port="161" svc_name="snmp" protocol="udp" severity="2" pluginID="99996" pluginName="SNMP Weaknesses" pluginFamily="Misc.">\n')
				f.write('<cvss3_base_score>5.0</cvss3_base_score>\n')
				f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
				f.write('<cvss_base_score>8.0</cvss_base_score>\n')
				f.write('<cvss_vector>CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C</cvss_vector>\n')
				f.write('<description>SNMP (Simple Network Management) Packets were captured. SNMP is used for device management and maintenance\n')
				f.write('The security of this protocol is provided by the authentication used.\n')
				f.write('SNMP packets are UDP datagrams which are therefore distributed across local LAN. SNMP version 1 and 2c packets are alsoclear text, which allows any threat actor on the LAN to capture the community strings and use them to glean information from device and potentially, modify device configuration.')
				f.write('</description>\n')
				f.write('<fname>snmp.nasl</fname>\n')
				f.write('<plugin_modification_date>2019/11/14</plugin_modification_date>\n')
				f.write('<plugin_name>SNMP Passive Analysis</plugin_name>\n')
				f.write('<plugin_publication_date>2019/11/14</plugin_publication_date>\n')
				f.write('<plugin_type>Passive</plugin_type>\n')
				f.write('<risk_factor>High</risk_factor>\n')
				f.write('<script_version>0.1</script_version>\n')
				f.write('<solution>InteliSecure recommends that SNMP version 1 and 2c are disabled and that SNMP version 3 is used instead.</solution>\n')
				f.write('<plugin_output>\n')
				snmptab = snmp.get_string()
				f.write(snmptab)
				f.write('</plugin_output>\n')
				f.write('</ReportItem>\n')

	if (len(cdp1src) or len(cdp2src) >1):
		f.write('<ReportItem port="none" svc_name="cdp" protocol="udp" severity="1" pluginID="99995" pluginName="CDP Information Disclosure" pluginFamily="Misc.">\n')
		f.write('<cvss3_base_score>3.3</cvss3_base_score>\n')
		f.write('<cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</cvss3_vector>\n')
		f.write('<cvss_base_score>8.0</cvss_base_score>\n')
		f.write('<cvss_vector>CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N</cvss_vector>\n')
		f.write('<description>CDP (Cisco Discovery Protocol) Packets were captured. CDP is used share information about directly connected Cisco equipment with other connected devices.\n')
		f.write('The CDP protocol is a proprietary Data Link layer protocol which broadcasts packets to all devices on the network. CDP packets include various information concerning the type of device, its capabilities and the Cisco IOS software version.')
		f.write('This information could be used by threat actors to research vulnerabilities in Cisco devices. Furthermore, the use of CDP is useful in the execution of many network protocol attacks. ')
		f.write('</description>\n')
		f.write('<fname>cdp.nasl</fname>\n')
		f.write('<plugin_modification_date>2019/11/25</plugin_modification_date>\n')
		f.write('<plugin_name>CDP Passive Analysis</plugin_name>\n')
		f.write('<plugin_publication_date>2019/11/25</plugin_publication_date>\n')
		f.write('<plugin_type>Passive</plugin_type>\n')
		f.write('<risk_factor>Low</risk_factor>\n')
		f.write('<script_version>0.1</script_version>\n')
		f.write('<solution>InteliSecure recommends that CDP is disabled where possible.</solution>\n')
		f.write('<plugin_output>\n')
		if len(cdp1src) > 1:
			cdptab = cdp1.get_string()
			f.write(cdptab)
		if len(cdp2src) > 1:
			cdp2tab = cdp2.get_string()
			f.write(cdp2tab)
			f.write('</plugin_output>\n')
			f.write('</ReportItem>\n')

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


	f.write('</ReportHost>\n')
	f.write("</Report>\n")
	f.write("</NessusClientData_v2>\n")
	f.close
 
