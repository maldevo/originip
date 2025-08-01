from datetime import datetime
from reconip import ReconIP
from validateip import ValidateIP
from concurrent.futures import ThreadPoolExecutor


if __name__ == "__main__":
	Recon = ReconIP()
	ParsedDomain = Recon.ParseArgs()
	print(f"[+] OriginIP Tool - Discover origin IPs behind WAF/CDN.\n[+] Author: Mahmoud Abdalkarim(@Maakthon)\n[+] Version: 1.0\n")
	Checkalive = Recon.CheckAlive(ParsedDomain)
	if Checkalive == 0:
		answer = input(f"[!] The hostname '{ParsedDomain}' could not be resolved. Do you want to continue? (y/n): ").strip().lower()
		if answer != "y":
			exit(1)
		else:
			print("[!] Continuing despite DNS resolution failure.")
		
	Recon.CheckWAF(ParsedDomain)
	print(f"\n[>] Recon initiated for: {ParsedDomain}")
	GetHash = Recon.FaviconHash(ParsedDomain)
	if len(Recon.ShodanKey) > 5: 
		Recon.ShodanSearch(ParsedDomain,GetHash)
		print("[+] Done Shodan search")
	if len(Recon.ViewdnsKey) > 5:
		Recon.ViewDNS(ParsedDomain)
		print("[+] Done ViewDNS search")
	if len(Recon.SecurityTrails) > 5:
		Recon.Securitytrails(ParsedDomain)
		print("[+] Done SecurityTrails search")
	if len(Recon.VirusTotal) > 5:
		Recon.Virustotal(ParsedDomain)
		print("[+] Done VirusTotal search")

	Recon.URLScan(ParsedDomain)
	print("[+] Done URLScan search")
	Recon.Alienvault(ParsedDomain)
	print("[+] Done Alienvault search")
	Recon.DNSHistory(ParsedDomain)
	print("[+] Done DNSHistory search")
	Recon.SPF(ParsedDomain)
	print("[+] Done SPF Record search")

	timestamp = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

	with open(f"./results/{ParsedDomain}-{timestamp}.txt","w") as f:
		for ip in Recon.AllSeenIPs:
			ip = ip.strip()
			ip = str(ip)
			f.write(ip)
			f.write("\n")
		f.close()

	print(f"\n[+] Successfully gathered {len(Recon.AllSeenIPs)} and saved raw recon IPs to ./results/{ParsedDomain}-{timestamp}.txt\n")

	# Assume ParsedDomain and Recon.AllSeenIPs are already set
	Validate = ValidateIP(ParsedDomain, Recon.AllSeenIPs)

	with ThreadPoolExecutor(max_workers=4) as executor:
	    executor.submit(Validate.ReverseIP, ParsedDomain, Recon.AllSeenIPs)
	    executor.submit(Validate.CheckHTTP, ParsedDomain, Recon.AllSeenIPs)
	    executor.submit(Validate.SSLCert, ParsedDomain, Recon.AllSeenIPs)
	    executor.submit(Validate.SANs, ParsedDomain, Recon.AllSeenIPs)


	#print(Validate.OriginIPs)

	with open(f"./results/{ParsedDomain}-validated-{timestamp}.txt","w") as f:
		for ip in Validate.OriginIPs:
			ip = ip.strip()
			ip = str(ip)
			f.write(ip)
			f.write("\n")
		f.close()

	with open(f"./results/{ParsedDomain}-map-{timestamp}.json","w") as f:
		for ip_host in Validate.IPHostname.items():
			ip_host = str(ip_host)
			f.write(ip_host)
			f.write("\n")
		f.close()

	print(f"\n[+] Successfully validated {len(Validate.OriginIPs)} and saved validated IPs to ./results/{ParsedDomain}-validated-{timestamp}.txt\n")
	print(f"\n[+] Successfully Map IP-Hostnames {len(Validate.OriginIPs)} and saved IP-Hostnames to ./results/{ParsedDomain}-map-{timestamp}.json\n")
