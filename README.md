# Snecky
A passive tool to simplify detection and reporting or network protocols with weak configurations and output stdout and to some standard output syles. Designed mostly for educational purposes for infrastructure testers to note weaknesses in network protocols where they are often overlooked. 

Currently supported protocols:

* OSPF
* VRRP
* HSRP
* CDP
* SNMP versions 1, 2c and 3
* VTP
* DTP
* 802.1q


snecky.py has been converted to Python 3 and tested using Python version 3.8.3. However, not fully tested in a live environment. 


Update to Snecky 26/04/2023

The following changes have been made:

    Nessus reporting has been removed.

The following protocols have been added:

    802.1q
    DTP
    VTP
    
    If you spot any issues please report them

TODO:
 
 * add more protocols 
 
 * Coming soon STP, 802.1X, WEP, WPA, WPA2
 
 * develop issue text

 * Nessus support has been removed. Support to be added for Dradis and a standardized XML report.  
 
 
Installation:

git clone https://github.com/liamromanis101/Snecky
 
sudo pip3 install -r requirements.txt
 
 
Usage:
 
sudo python3 snecky.py
