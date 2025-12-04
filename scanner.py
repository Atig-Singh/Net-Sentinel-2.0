import nmap
import socket
import sys
import json
if len(sys.argv) > 1:
    target_ip = sys.argv[1]

def analyze_risk(port, service_name):
    risk = "low"
    info = f"Standard {service_name} service"
    if port == 21:
        risk = "high"
        info = "FTP: Insecure file transfer. Check anonymous login."
    elif port == 23:
        risk = "high"
        info = "Telnet: Unencrypted traffic. Passwords visible!"
    elif port == 80 or port == 8080:
        risk = "medium"
        info = "HTTP: Web server without encryption."
    elif port == 3306:
        risk = "medium"
        info = "MySQL: Database exposed to network."
    elif port == 3389:
        risk = "high"
        info = "RDP: Remote Desktop. Brute-force target."
    elif port == 443:
        risk = "low"
        info = "HTTPS: Secure encrypted web traffic."
    elif port == 22:
        risk = "low"
        info = "SSH: Secure remote access."

    return risk, info

def guess_device_type(host_data, open_ports):
  
    guessed_type = "Unknown Device"
    
    if 'vendor' in host_data and host_data['vendor']:
        vendor_name = list(host_data['vendor'].values())[0].lower()
        
        if "apple" in vendor_name: return "Apple Device"
        if "espressif" in vendor_name: return "Smart Home (IoT)"
        if "raspberry" in vendor_name: return "Raspberry Pi"
        if "canon" in vendor_name or "hp" in vendor_name or "epson" in vendor_name: return "Printer"
        if "synology" in vendor_name: return "NAS Server"
    if 631 in open_ports: return "Printer"         
    if 554 in open_ports: return "IoT Camera"     
    if 53 in open_ports: return "Router/Gateway"   
    if 3389 in open_ports: return "Windows PC"     
    if 22 in open_ports and 80 not in open_ports: return "Linux Server"
    if 80 in open_ports or 443 in open_ports: return "Web Server"
    
    return "Workstation"
ip=target_ip
nm=nmap.PortScanner()
output_list=[]
scanning=nm.scan(hosts=ip,ports="20-9000",arguments="-sT -T4")
for host in nm.all_hosts():
    open_ports_list = []
    vuln_list = []
    for proto in nm[host].all_protocols():
        for port in (nm[host][proto].keys()): 
            state = nm[host][proto][port]["state"]

            if state == "open":
                open_ports_list.append(port)
                service = nm[host][proto][port]["name"]
                risk_status,info_status=analyze_risk(port,service)
                vuln_list.append({
                    "port": port,
                    "service": service,
                    "risk": risk_status,
                    "info": info_status
                })
        device=guess_device_type(nm[host],open_ports_list)
        output_list.append({
        "ip": host,
        "type": device,
        "vulns": vuln_list
        })
print(json.dumps(output_list))
