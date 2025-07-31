import io
import re
import sys
import ssl
import mmh3
import base64
import shodan
import socket
import hashlib
import requests
import argparse
import subprocess
import dns.resolver
from OpenSSL import crypto
from collections import deque
from ipaddress import IPv4Address
from ssl import get_server_certificate
from urllib.parse import urljoin, urlparse

class ValidateIP:
	def __init__(self,DomainName,AllSeenIPs):
		print(f"\n[>] Starting validation of {len(AllSeenIPs)} IP addresses")
		self.OriginIPs = set()
		self.DeadIPs = set()
		self.IPHostname = dict()
		

	def ReverseIP(self,DomainName,AllSeenIPs):
		for ip in AllSeenIPs:
			try:
				hostname,_,_ = socket.gethostbyaddr(ip)
				if hostname in DomainName:
					if ip not in self.OriginIPs:
						self.OriginIPs.add(ip)
					# ADD ip and host as a dict  to self.IPHostname 
					self.IPHostname[ip] = hostname
			except:
				continue		

	def CheckHTTP(self,DomainName,AllSeenIPs):
		for ip in AllSeenIPs:
			try:
				URL = f"http://{ip}"
				URL2 = f"https://{ip}"
				headers = {"Host":DomainName}
				try:
					response = requests.get(URL, headers=headers, timeout=15,allow_redirects=False, verify=False)
				except Exception as err:
					#print(err)
					continue
				if DomainName in response.text or response.status_code in [200,301,302,303,307,308]:
					if ip not in self.OriginIPs:
						self.OriginIPs.add(ip)
					self.IPHostname[ip] = DomainName
				try:
					response2 = requests.get(URL2, headers=headers, timeout=15,allow_redirects=False, verify=False)
				except:
					continue
				if DomainName in response2.text or response.status_code in [200,301,302,303,307,308]:
					if ip not in self.OriginIPs:
						self.OriginIPs.add(ip)
					self.IPHostname[ip] = DomainName
			except Exception as err:
				print(err)
				continue

	def SSLCert(self,DomainName,AllSeenIPs):
		for ip in AllSeenIPs:
			#print(DomainName)
			try:
				ctx = ssl.create_default_context()
				with ctx.wrap_socket(socket.socket(), server_hostname=DomainName) as s:
					s.settimeout(5)
					s.connect((ip, 443))
					cert = s.getpeercert()
					subject = dict(x[0] for x in cert.get("subject", []))
					cn = subject.get("commonName", "")
					if DomainName in cn:
						if ip not in self.OriginIPs:
							self.OriginIPs.add(ip)
				#print(f"{ip},{cn}")
				# ADD ip and host as a dict  to self.IPHostname 
				self.IPHostname[ip] = cn
			except:
				continue

	def SANs(self,DomainName,AllSeenIPs):
		SLD = DomainName.split(".")[-2]
		for ip in AllSeenIPs:
			try:
				socket.setdefaulttimeout(5)
				# Fetch the PEM-formatted certificate from the IP'
				cert_pem = get_server_certificate((ip, 443))
				cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

				# Loop through the certificate's extensions
				for i in range(cert.get_extension_count()):
					ext = cert.get_extension(i)
					if ext.get_short_name() == b'subjectAltName':
					# Extract and split SANs
						san_entries = str(ext).split(', ')
						if SLD in str(san_entries):
							if ip not in self.OriginIPs:
								self.OriginIPs.add(ip)
							self.IPHostname[ip] = str(san_entries)

			except Exception as err:
				#print(f"[!] Error getting SAN from {ip}: {err}")
				continue
