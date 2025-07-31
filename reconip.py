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
from ipaddress import IPv4Address, IPv4Network
from ssl import get_server_certificate
from urllib.parse import urljoin, urlparse


class ReconIP:
	def __init__(self,ConfigFile="APIs.conf"):
		self.ApiKeys = self.LoadAPIs(ConfigFile)
		self.ShodanKey = self.ApiKeys.get("shodan")
		self.ViewdnsKey = self.ApiKeys.get("viewdns")
		self.SecurityTrails = self.ApiKeys.get("securitytrails")
		self.AlienVault = self.ApiKeys.get("alienvault")
		self.VirusTotal = self.ApiKeys.get("virustotal")

		self.IPv4Queue = deque() #append
		self.AllSeenIPs = set()  #add
		#self.hostname = hostname
		pass

	# Load the APIs from APIs.conf file
	def LoadAPIs(self,filename):
		keys = {}
		try:
			with open(filename,"r") as f:
				APIs = f.read().split("\n")
				for api in APIs:
					if "=" in api:
						key,value = api.split("=",1)
						keys[key.strip()] = value.strip()
		except FileNotFoundError:
			 print(f"Config file '{filename}' not found.")
		return keys

	# Return the domain name
	def ParseArgs(self):
	    parser = argparse.ArgumentParser(
	        description="OriginIP Tool v1 - Discover origin IPs behind WAF/CDN - @Maakthon"
	    )
	    parser.add_argument(
	        "-u", "--url",
	        required=True,
	        help="Target full URL (e.g., https://maakthon.com)"
	    )
	    args = parser.parse_args()
	    ParsedUrl = self.ParseURL(args.url)

	    return ParsedUrl

	# Extract the network location or hostname of the URL
	def ParseURL(self,url):
		try:
			result = urlparse(url)
			if result.netloc == '':
				print(f"[!] Enter full FQDN (e.g., https://{url})")
				exit(1)
			else:
				return result.netloc
		except Exception as err:
			print(err)

	# Check this hostname is a live or not exsists checking using DNS gethostbyname() and ICMP ping.
	def CheckAlive(self,parsed):
		try:
			IP = socket.gethostbyname(parsed)
			if IP:
				for ip in socket.getaddrinfo(parsed, None):
					try:
						if IPv4Address(ip[4][0]) and ip[4][0] not in self.AllSeenIPs:
							#print(ip[4][0])
							self.AllSeenIPs.add(ip[4][0])
							self.IPv4Queue.append(ip[4][0])
					except:
						continue
			return 1

		except socket.gaierror:
			#print(f"[!] Could not resolve {parsed}")
			return 0

	# Check if the website behind a WAF or not 		
	def CheckWAF(self,parsed):
		try:
			result = subprocess.run(
			["wafw00f", parsed],
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			text=True
			)
			output = result.stdout.strip()
			#print(output)

			if "behind" in output:
			# Extract the WAF name from output
				detected = output.split("behind")[-1].strip()
				detected = detected.split("WAF.")[0]
				if detected:
					print(f"[>] WAF Detected: {detected}")
				return detected
		except Exception as err:
			print(err)
			return None

	# Get the favicon of the URL and Calc the hash of it.
	def FaviconHash(self,parsed):
		URL = f"{parsed}"
		AllFavicons = set()
		AllFaviconsHash = set()

		headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100'}
		try:
			favURL = f"http://{URL}/favicon.ico" 
			response = requests.get(favURL,headers=headers,timeout=10,allow_redirects=True)
			if response.status_code == 200:
				#print(f)
				b64_favicon = base64.encodebytes(response.content)
				favicon_hash = mmh3.hash(b64_favicon)
				AllFaviconsHash.add(favicon_hash)
				#print(AllFaviconsHash)
				return AllFaviconsHash
			else:
				URL2 = f"http://{URL}"
				response2 = requests.get(URL2,headers=headers,timeout=10, allow_redirects=True)
				pattern = r'<link[^>]+rel=["\']?(?:shortcut\s+icon|icon)["\']?[^>]*href=["\']?([^"\'>]+\.ico)["\']?'
				PageContent = response2.text
				AllIcons = re.findall(pattern, PageContent, flags=re.IGNORECASE)
				for icon in AllIcons:
					# Check relative or absolute
					parse = urlparse(icon)
					if parse.scheme in ["http","https"]:
						AllFavicons.add(icon)
					else:
						fullurl = urljoin(URL2,icon)
						AllFavicons.add(fullurl)
				for i in AllFavicons:
					try:
						res = requests.get(i,headers=headers,timeout=10)
					except:
						continue
					b64_favicon = base64.encodebytes(res.content)
					favicon_hash = mmh3.hash(b64_favicon)
					if favicon_hash not in AllFaviconsHash:
						AllFaviconsHash.add(favicon_hash)
				#print(AllFaviconsHash)		
				return AllFaviconsHash
				
		except Exception as err:
			print(err)

	# 
	def ShodanSearch(self,parsed,iconHash):
		queries = {
		"domain": parsed,
		"ssl": f'ssl:"{parsed}"',
		"sslCN": f'ssl.cert.subject.CN:"{parsed}"',
		"sslSubject": f'ssl.cert.subject:"{parsed}"',
		"host": f'http.host:"{parsed}"',
		"hostname": f'hostname:"{parsed}"',
		"org": f'org:"{parsed}"'
		}
		if iconHash:
			HashValue = next(iter(iconHash))
			if HashValue:
				queries["favicon"] = f"http.favicon.hash:{HashValue}"

		# Loop for every query in the dict and search in shodan
		try:
			API = shodan.Shodan(self.ShodanKey)
			for name,query in queries.items():
				results = API.search(query)
				for result in results["matches"]:
					# Get only IPv4 with its port
					if IPv4Address(result["ip_str"]):
						IPv4 = f'{result["ip_str"]}:{result["port"]}'
						if IPv4 not in self.AllSeenIPs:
							self.AllSeenIPs.add(IPv4)
							self.IPv4Queue.append(IPv4)
						#print(IPv4)
		except Exception as err:
			print(err)

	# Find Historical IP Addresses for the domain
	def ViewDNS(self,parsed):
		URL = f"https://api.viewdns.info/iphistory/?domain={parsed}&apikey={self.ViewdnsKey}&output=json"
		try:
			response = requests.get(URL,timeout=10)
			response = response.json()
			IPs = [record['ip'] for record in response['response']['records']]
			for ip in IPs:
				if ip not in self.AllSeenIPs:
					self.AllSeenIPs.add(ip)
					self.IPv4Queue.append(ip)
			#print(self.AllSeenIPs)
		except Exception as err:
			print(err)

	# Find Historical IP Addresses
	def Securitytrails(self,parsed):
	    URL = f"https://api.securitytrails.com/v1/history/{parsed}/dns/a"
	    headers = {"APIKEY":self.SecurityTrails,"Content-Type":"application/json"}
	    try:
	        response = requests.get(URL,headers=headers,timeout=15)
	        data = response.json()
	        for record in data.get("records",[]):
	            for value in record.get("values",[]):
	                IP = value.get("ip")
	                #print(IP)
	                if IP not in self.AllSeenIPs:
	                	self.AllSeenIPs.add(IP)
	        #print(self.AllSeenIPs)
	    except Exception as err:
	        print(err)

	def Virustotal(self,parsed):
		# 
		URL = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={self.VirusTotal}&domain={parsed}"
		try:
			response = requests.get(URL,timeout=20)
			data = response.json()
			IPAddresses = [res["ip_address"] for res in data["resolutions"]]
			for ip in IPAddresses:
				try:
					if IPv4Address(ip):
						if ip not in self.AllSeenIPs:
							self.AllSeenIPs.add(ip)
				except:
					continue
		except Exception as err:
			print(err)

	def URLScan(self,parsed):
		URL = f"https://urlscan.io/api/v1/search/?q=domain:{parsed}&size=10000"
		headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100'}

		try:
			response = requests.get(URL,headers=headers,timeout=10)
			data = response.json()
			for entry in data.get("results"):
				page = entry.get("page",{})
				IP = page.get("ip")
				try:
					if IPv4Address(IP):
						if IP not in self.AllSeenIPs:
							self.AllSeenIPs.add(IP)
				except:
					continue
		except Exception as err:
			print(err)

	# Get all IPs from Alienvault using API if provided and normal scrape if API nor 
	def Alienvault(self,parsed):
		labels = parsed.strip().split(".")
		if len(labels) == 2:
			URL = f"https://otx.alienvault.com/api/v1/indicators/domain/{parsed}/url_list?limit=100000000"
		else:
			URL = f"https://otx.alienvault.com/api/v1/indicators/hostname/{parsed}/url_list?limit=100000000"
		if len(self.AlienVault) > 3:
			# API 
			headers = {"X-OTX-API-KEY":self.AlienVault}
			try:
				response = requests.get(URL,headers=headers,timeout=30)
			except:
				pass
			data = response.json()
			data = data["url_list"]
			for entry in data:
				IP = entry.get("result", {}).get("urlworker", {}).get("ip")
				try:
					if IPv4Address(IP):
						if IP not in self.AllSeenIPs:
							self.AllSeenIPs.add(IP)
				except:
					continue

		else:
			# Normal Scrape
			try:
				response = requests.get(URL,timeout=30)
			except:
				pass
			data = response.json()
			data = data["url_list"]
			for entry in data:
				IP = entry.get("result", {}).get("urlworker", {}).get("ip")
				try:
					if IPv4Address(IP):
						if IP not in self.AllSeenIPs:
							self.AllSeenIPs.add(IP)
				except:
					continue

			
	# Get DNS historical IPs from dnshistory.org		
	def DNSHistory(self,parsed):
		URL = f"https://dnshistory.org/historical-dns-records/a/{parsed}"
		headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100'}
		pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
		try:
			response = requests.get(URL,headers=headers,timeout=20)
			IPs = re.findall(pattern,response.text)
			for ip in IPs:
				try:
					if IPv4Address(ip):
						if ip not in self.AllSeenIPs:
							self.AllSeenIPs.add(ip)
				except:
					continue
		except Exception as err:
			print(err)

	def SPF(self,parsed):
		try:
			answers = dns.resolver.resolve(parsed, "TXT")
			for rdata in answers:
				for txt in rdata.strings:
					if isinstance(txt, bytes):
						txt = txt.decode()

					if txt.startswith("v=spf1"):
						for part in txt.split():
							if part.startswith("ip4:"):
								ip = part.split("ip4:")[1]
								if "/" in ip:
									#print(ip)
									try:
										net = IPv4Network(ip, strict=False)
										for ipv4 in net:
											#print(ipv4)
											if ipv4 not in self.AllSeenIPs:
												self.AllSeenIPs.add(str(ipv4))
									except:
										pass
								else:
									try:
										if IPv4Address(ip):
											if ip not in self.AllSeenIPs:
												self.AllSeenIPs.add(ip)
									except:
										continue
		except Exception as err:
			print(f"[!] Error parsing SPF records for {parsed}: {err}")