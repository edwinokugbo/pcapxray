# PcapXray [![Build Status](https://travis-ci.org/Srinivas11789/PcapXray.svg?branch=master)](https://travis-ci.org/Srinivas11789/PcapXray) [![codecov](https://codecov.io/gh/Srinivas11789/PcapXray/branch/master/graph/badge.svg)](https://codecov.io/gh/Srinivas11789/PcapXray) [![defcon27](https://img.shields.io/badge/defcon27-demolabs-blue)](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html#PcapXray)
    A Network Forensics Tool - To visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction
![Alt text](https://srinivas11789.github.io/PcapXray/logo.png?width=20px "PcapXray")
## PcapXray Design Specification
Wiki has more help too.

### Goal:
  Given a Pcap File, plot a network diagram displaying hosts in the network, network traffic, highlight important traffic and Tor traffic as well as potential malicious traffic including data involved in the communication.

### Problem:
* Investigation of a Pcap file takes a long time given initial glitch to start the investigation
*	Faced by every forensics investigator and anyone who is analyzing the network

* Location: https://github.com/Srinivas11789/PcapXray

### Solution: Speed up the investigation process
* Make a network diagram with the following features from a Pcap file
Tool Highlights:
* Network Diagram – Summary Network Diagram of full network
* Information: 
  * Web Traffic with Server Details
  * Tor Traffic
  * Possible Malicious traffic
  * Data Obtained from Packet in Report – Device/Traffic/Payloads
  * Device Details
  
### Tool Image:
![Alt text](?raw=true)

![Alt text](?raw=true)

### Components:
* Network Diagram 
* Device/Traffic Details and Analysis
* Malicious Traffic Identification
* Tor Traffic
* GUI – a gui with options to upload pcap file and display the network diagram

### Setup 

* Python 3

* Unzip the files to a folder e.g. pcapxray
* Or clone it from the github page
8 navigate to the folder e.g. cd pcapxray

```bash
apt install python3-pip
Create a virtual environment with venv
    apt-get install python3-venv
    mkdir pcapenv
    python3 -m venv pcapenv
    source pcapenv/bin/activate         
pip install -r requirements.txt
python manage.py runserver --no-reload
```
The above commands have also been saved in an executable file name pc in the project root directory.

( You may escalate your user privilege to allow file creations if your system requires it - Run with `sudo` )

( Make sure to escalate privilege to allow file creations - Run with `sudo` )

### Python Libraries Used:  - All these libraries are required for functionality
* All these are included in the requirements.txt file
  * Scapy – rdpcap to read the packets from the pcap file 
  *	Ipwhois – to obtain whois information from ip
  *	Netaddr – to check ip information type
  *	Pillow – image processing library
  *	Stem – tor consensus data fetch library
  *	pyGraphviz – plot graph
  *	Networkx – plot graph
  *	Matplotlib – plot graph (not used as of now)
  
### Demo
![Alt text](?raw=true)

### Getting started:
* Clone the repository
* pip install -r requirements.txt
* python manage.py runserver --noreload

### Additional Information:
* Tested on Linux
* Options for Traffic include - Web (HTTP and HTTPS), Tor, Malicious, ICMP, DNS
 
### Challenges:
  * Performance and Timing:
    * The main challenged face was understanding the packet data and what each item meant. Once that is understood, the work becomes easier 
    * The performance and timing of the total application was a big challenge with different data gathering and output generation

*	Current Fix in rare occasions: If any of the above issue occurs the progress bar keeps running and no output is generated, a restart of the app would be required.

### Docker Containers of PcapXray
* Dockerfile present in the root folder was used to build images
* Already built docker images are found at dockerhub
  - srinivas11789/pcapxray-1.0
  - srinivas11789/pcapxray-2.2
* Performing the steps in `run.sh` file manually would work to launch the tool via docker (I can help with errors)
* Running `run.sh` scripts is an attempt to automate (would not work 100 percent)
  - tested on mac and linux - will be better soon!...

### Immediate Future Tasks: (Target: 3.0)

- Clean up code (beautify code base from being a prototype)
- Report generation on unique folders for all assets of a packet capture
- Suspicious activity detection
- Support more pcap reader engine
- Traffic support: ICMP, DNS
- Known file type detection and Extract
- Python2 and Python3
- Interactive map

### Future:
* Structured and clean code flow
*	Change the database from JSON to sqlite or prominent database, due to memory hogging
*	Change fronend to web based such as Django
*	Make the application more stable
* More protocol support
* Clean up code

### Credits:
* Thanks for making it better,
  - Professor Marc Budofsky
  - Kevin Gallagher
* Thanks for all the dependent libraries used
* Logo created with logomakr.com and www.inkscape.org

[![Analytics](https://ga-beacon.appspot.com/UA-114681129-1/PcapXray/readme)](https://github.com/igrigorik/ga-beacon)

## ***Just for Security Fun!***
