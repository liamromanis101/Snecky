# Snecky
A passive tool to simplify detection and reporting or network protocols with weak configurations and output into a Nessus like format for import to reporting tools. 

Currently supported protocols:

* OSPF
* VRRP
* HSRP
* CDP
* SNMP versions 1 and 2c. SNMPv3 support not completed. 


snecky.py has been converted to Python 3 and tested using Python version 3.8.3. However, not fully tested in a live environment. 


Update to Snecky 26/04/2023

The following changes have been made:

    Nessus reporting has been removed.

The following protocols have been added:

    802.1q
    DTP
    VTP

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
