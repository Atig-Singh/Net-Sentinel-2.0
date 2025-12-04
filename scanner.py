import nmap
import socket
import sys
import json
if len(sys.argv) > 1:
    target_ip = sys.argv[1]

def analyze_risk(port, service_name):
    risk = "low"
    info = f"Standard {service_name} service"
    fix = "Ensure service is patched and updated."
    if port == 21:
        risk = "high"
        info = "FTP: Insecure file transfer. Data sent in cleartext."
        fix = "Disable FTP. Use SFTP (Port 22) or FTPS instead."
    elif port == 23:
        risk = "high"
        info = "Telnet: Unencrypted remote access. Passwords visible!"
        fix = "CRITICAL: Disable immediately. Use SSH (Port 22)."
    elif port == 445:
        risk = "high"
        info = "SMB: Windows File Sharing. Vulnerable to Ransomware."
        fix = "Block Port 445 on Firewall. Disable SMBv1 protocol."
    elif port == 3389:
        risk = "high"
        info = "RDP: Windows Remote Desktop exposed to internet."
        fix = "Place behind a VPN or restrict access via Firewall."
    elif port == 5900:
        risk = "high"
        info = "VNC: Remote Desktop. Often has weak passwords."
        fix = "Tunnel VNC through SSH or use a VPN."
    elif port == 80 or port == 8080:
        risk = "medium"
        info = "HTTP: Web traffic is unencrypted."
        fix = "Enforce HTTPS (Port 443) with a valid SSL certificate."
    elif port == 3306:
        risk = "medium"
        info = "MySQL: Database listening on network."
        fix = "Bind to localhost (127.0.0.1) or restrict IP access."
    elif port == 5432:
        risk = "medium"
        info = "PostgreSQL: Database listening on network."
        fix = "Configure pg_hba.conf to restrict remote connections."
    elif port == 25:
        risk = "medium"
        info = "SMTP: Email Relay. Can be used for spam."
        fix = "Disable open relay configuration."
    elif port == 554:
        risk = "medium"
        info = "RTSP: Camera stream. Often has weak/default credentials."
        fix = "Update camera firmware and set a strong password."
    elif port == 5555:
        risk = "medium"
        info = "ADB: Android Debug Bridge exposed."
        fix = "Disable 'Wireless Debugging' on the Android device."
    elif port == 22:
        risk = "low"
        info = "SSH: Secure remote access."
        fix = "Use Key-based authentication and disable root login."
    elif port == 443:
        risk = "low"
        info = "HTTPS: Secure encrypted web traffic."
        fix = "Ensure TLS 1.2/1.3 is enabled."
    elif port == 53:
        risk = "low"
        info = "DNS: Domain Name Service."
        fix = "Ensure recursion is disabled if not public."
    elif port == 631:
        risk = "low"
        info = "IPP: Internet Printing Protocol."
        fix = "Restrict access to local network only."

    return risk, info, fix
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
scanning=nm.scan(hosts=ip,ports="20-1024,3306,8080,5555,554,631",arguments="-sT -T4")#NORMAL SCAN
#scanning=nm.scan(hosts=ip,arguments="-sV --script vuln")#DEEP SCAN
for host in nm.all_hosts():
    open_ports_list = []
    vuln_list = []
    for proto in nm[host].all_protocols():
        for port in (nm[host][proto].keys()): 
            state = nm[host][proto][port]["state"]

            if state == "open":
                open_ports_list.append(port)
                service = nm[host][proto][port]["name"]
                risk_status,info_status,fix_status=analyze_risk(port,service)
                vuln_list.append({
                    "port": port,
                    "service": service,
                    "risk": risk_status,
                    "info": info_status,
                    "remediation": fix_status
                })
        device=guess_device_type(nm[host],open_ports_list)
        output_list.append({
        "ip": host,
        "type": device,
        "vulns": vuln_list
        })
print(json.dumps(output_list))
