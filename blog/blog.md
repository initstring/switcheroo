Switcheroo - Universal SSRF Attack Primitive for Windows Systems

# Introduction

## Overview
Remote, unauthenticated attackers can force stock Windows systems on the same local area network to perform arbitrary HTTP GET requests, including to their own localhost interface. No user interaction is required. No IIS installation is required. Network Discovery must be enabled to trigger the exploit (usually on by default for private networks). The response cannot be viewed by the attacker, making this a "Blind Server-Side Request Forgery" vulnerability.

This provides an exploit primitive that can be used for attacking services like REST APIs. Applications deployed only to localhost, or those on protected network segments, are exposed to attackers due to this OS vulnerability.

This is done by responding to SSDP multicast discovery requests, which Windows systems send out automatically and at regular intervals. These requests ask for a URL to learn more about available shared devices on a LAN. Windows will ignore the host portion of any advertised URL, connecting only to the host who provided the advertisement. However, a malicious host can reply to that connection with an HTTP 301 redirect. Windows will process the redirection completely, accepting any arbitrary host (including 127.0.0.1) and URL path.

![diagram](ssrf-diagram.jpg)

While this write-up is specific to the vulnerable SSDP service in Windows, it is likely that many other applications using their own SSDP stack are vulnerable as well.

Exploit POC code is available in the GitLab repository [here](https://gitlab.com/initstring/switcheroo).

## Vulnerable Windows OS Versions
The exploit POC was tested on the following versions of Windows, all of which were vulnerable:
- Windows 10 Enterprise Insider Preview v1903 (build 18932.1000)
- Windows 10 Enterprise v1903 (build 18362.30)
- Windows Server 2016 Standard v1607 (build 14393.693)

# Details

## SSDP Discovery Process
Simple Service Discovery Protocol (SSDP) is used by Operating Systems (Windows, MacOS, Linux, IOS, Android, etc) and applications (Spotify, Youtube, etc) to discover shared devices on a local network. It is the foundation for discovering and advertising Universal Plug & Play (UPNP) devices.

The cool thing about SSDP, for an attacker, is that there are no real security mechanisms built in. A machine using SSDP to discover devices will send clear-text messages to everyone on the LAN and trust any device that replies.

Devices attempting to discover shared network resources will send a UDP multicast out to 239.255.255.250 on port 1900. The source port is randomized. An example request looks like this:

```
M-SEARCH * HTTP/1.1
Host: 239.255.255.250:1900
ST: upnp:rootdevice
Man: "ssdp:discover"
MX: 3
```

Any device on the local area network can respond to that request, providing a URL that points to an XML document called a 'Device Descriptor'. This reply looks like the following:

```
HTTP/1.1 200 OK
CACHE-CONTROL: max-age=1800
DATE: Tue, 16 Oct 2018 20:17:12 GMT
EXT:
LOCATION: http://192.168.1.214:8888/ssdp/device-desc.xml
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: uuid:7f7cc7e1-b631-86f0-ebb2-3f4504b58f5c
SERVER: UPnP/1.0
ST: upnp:rootdevice
USN: uuid:7f7cc7e1-b631-86f0-ebb2-3f4504b58f5c::upnp:rootdevice
BOOTID.UPNP.ORG: 0
CONFIGID.UPNP.ORG: 1
```

Once the Windows system receives this reply, it will then initiate an HTTP GET request to the location specified in the `LOCATION` header above. 

## Abusing SSDP for SSRF
While the example above provides an IP address (192.168.1.214), Windows will completely ignore that. For example, if the `LOCATION` header specified `http://127.0.0.1/device.xml`, Windows would pay attention only to the `/device.xml` and perform an HTTP GET to that URL on the remote host that responded to the discovery request. This is a way to prevent SSRF.

However, if that remote host were to respond with an HTTP 301 redirect when queried at `/device.xml`, Windows will trust the full URL provided in a new `LOCATION` header.

This can be demonstrated as follows:
- Connect the attacking box, running Linux, to the same LAN subnet as a Windows machine.
- On the Windows machine, run some listener to verify SSRF, like ncat as follows:

```
ncat.exe -nlvp 4444
```

- Run the following from the Linux attack box, replacing eth0 with the appropriate LAN interface:

```
python3 switcheroo.py -i eth0 -u http://localhost:4444/ssrf_pwn -t "*"
```

- SSDP Disovery happens on a regular basis in Winows. So you can simply wait, or do the following on the Windows target to speed things up:
  - Open Windows Explorer
  - Select "Network" from the left
  - Click the refresh button in the address bar

From here, you will see the Windows machine connect to itself on localhost, which should be protected. This attack can be customized with switcheroo.py by providing an SSRF URL targeted at any application.

![screenshot](screenshot.png)

## Weaponization
My free time is a bit limited right now due to a new gig and just life in general. I'm releasing this info and POC in the hopes that other hackers can build some cool exploit chains with it. I would love to hear feedback from folks who have success.

As most administrators would not imagine a default installation of Windows to even have a remote SSRF attack footprint, I suspect there is some juicy bugs out there. Happy hunting.

## More Info
This discovery came as a byproduct of my earlier research into SSDP vulnerabilities, which you can read more about on the evil-ssdp page [here](https://gitlab.com/initstring/evil-ssdp).


## Disclosure Timeline
- Initial report to Microsoft:
