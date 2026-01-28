#!/usr/bin/python
import subprocess as sub
import re
import socket


def resolve_target(target):
    """
    Returns the IP address of a hostname or validates an existing IP.
    """
    try:
        # This handles both hostnames (google.com) and IP strings (8.8.8.8)
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        # gaierror stands for "getaddrinfo error"
        return f"Error: Could not resolve '{target}'. Check your connection or the address."


my_nat_ip_addr = re.findall(
    r'192\.[^\s]*', str(sub.run(['ifconfig'], capture_output=True).stdout))[0]

cached_hosts = {}
allowed_countries = {'IR'}
bufsize = 10000
f = open('cached_hosts', 'r+', buffering=bufsize)
for line in f:
    cached_hosts[line.strip()] = 1
p = sub.Popen(('sudo', 'tcpdump', '-l', 'dst',
              my_nat_ip_addr), stdout=sub.PIPE)
for row in iter(p.stdout.readline, b''):
    hostname_or_ips = re.findall(r'IP\s+([^\s]+)\.[^\s]+', str(row.rstrip()))
    for hostname_or_ip in hostname_or_ips:
        ips = [resolve_target(hostname_or_ip)]
        for ip in ips:
            if not ip or ip in cached_hosts:
                continue
            cntry_full = str(
                sub.run(['geoiplookup', ip], capture_output=True).stdout)
            try:
                country = re.findall(
                    r'.*Edition:\s*([^,]+),.*', cntry_full)[0]
            except:
                continue
            if country not in allowed_countries:
                if sub.call(['sudo', 'ufw', 'deny', 'from', ip]) == 0:
                    print("BLOCKED:  " +
                          ip + " from country " + country)
                    cached_hosts[ip] = 1
                    f.write(ip + '\n')
                else:
                    print("Failed to add firewall rule for:" + ip)
            else:
                print("ALLOWED: " +
                      ip + " from country " + country)
            # we do not write sources allowed through firewall to file
            # in case we want to block them later
            cached_hosts[ip] = 1

f.close()
