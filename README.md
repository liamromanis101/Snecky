# Snecky
A passive tool to simplify detection and reporting or network protocols with weak configurations and output into a Nessus like format for import to reporting tools. 

Currently supported protocols:

* OSPF
* VRRP
* HSRP
* CDP
* SNMP versions 1 and 2c. SNMPv3 support not completed. 


snecky-0.9.2a.py has been converted to Python 3 and tested using Python version 3.8.3. However, not fully tested in a live environment. 


TODO:

 * shit loads!
 
 * add more protocols
 
 * develop issue text
 
 * develop library to support creation of '.nessus' reports.
 
 * STP support in development
 
 
Installation:

git clone https://github.com/liamromanis101/Snecky
 
sudo pip3 install -r requirements.txt
 
 
Usage:
 
sudo python3 snecky.py
