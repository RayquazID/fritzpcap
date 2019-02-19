# fritzpcap
### make a packet capture on the whole lan traffic and create a datastream.pcap

tested with FRITZ!Box 7430 on FRITZ!OS 06.83

at the moment, this is just for my personal use and pretty raw
you have to define some default variables before use.
I'll make an interactive way to input these soon
other planned impovements:
 - list all possible interfaces to capture on
 - select interface to capture
 - command line arguments
 - selecting output location

if someone has suggestions on making this little project better, let me know

#### Usage
```bash
./fritzpcap.py <TIME TO CAPTURE IN SECONDS>
```

Variables to setup:
 - url = '' # Your IP Adress
 - user = '' # Your Username optional
 - passwd = '' # Your Password
 - target_path = './datastream.pcap' # Your output location
 - interface ='1-lan' # Default interface

#### Requirements
Install requests
```bash
pip install requests
```
