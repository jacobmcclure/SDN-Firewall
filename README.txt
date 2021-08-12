Jacob McClure
jatmcclu@ucsc.edu


Files & Their Contents:


firewall_controller.py: 
This is my python script for the SDN firewall, which regulates TCP/ARP/ICMP traffic. The current 
rules are quite simple: host 1 and host 3 are the only hosts I have allowed to communicate using TCP.
Any other TCP packets will be dropped. Any host in this network can communicate using ARP or ICMP, 
but any other packets besides these will be dropped. 

To use this application, you will need to install a MiniNet VM and boot into it. From there, you'll
want to open the command line and store a local copy of both the controller and topology files on
the VM. Store both files in a new directory called pox/pox.py, located in ~ (so the path will be
~/pox/pox.py). Once the files are in this directory, you can run the program!
Now, go to the command line and enter: 
> sudo ~/pox/pox.py misc.firewall_controller
followed by:
> sudo python ~/topology.py

Now, you can test the firewall using basic commands such as iperf, ping, pingall, dump, etc.
