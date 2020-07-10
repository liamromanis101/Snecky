Hi
If you wish to contribute to this project there are several ways you can do this....

The main way to 'encourage' addition protocol support is to perform the following:

nano snecky-0.9.2a.py 

goto line 267 and find the line shown below:

                pkt=sniff(count=c,iface=intf,prn=print_pkt)

The change this line to 

                pkt=sniff(count=c,iface=intf,prn=print_pkt2)

Then when you run the tool is will print out scapy packets which can be used to develop support for additional protocols and new versions of protocols already supported. Enter the packet text into a  

Thanks for your support

Liam
                
