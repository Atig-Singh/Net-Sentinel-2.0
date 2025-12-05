import nmap
import socket
import sys
import json

target_ip = ""
stealth_mode = "false"

if len(sys.argv) > 1:
    target_ip = sys.argv[1]
if len(sys.argv) > 2:
    stealth_mode = sys.argv[2] # Passed as string "true" or "false"

def analyze_risk(port, service_name, product="", version="", cves=[]):
    risk = "low"
    info = f"Standard {service_name} service"
    
    # Enrich info with product/version if available
    if product:
        info = f"{product} {version} ({service_name})".strip()

    # CRITICAL: Elevate risk if CVEs are found
    if cves:
        risk = "high"
        info += f" | {len(cves)} VULNERABILITIES DETECTED: " + "; ".join(cves)[:200] + "..."

    fix = "Ensure service is patched and updated."

    # Heuristic Checks (Keep these for quick categorization even if no CVEs found)
    if risk == "low": # Only apply strict heuristics if not already flagged by CVEs
        if port == 21:
            risk = "high"
            info += " (FTP Insecure)"
            fix = "Disable FTP. Use SFTP (Port 22) or FTPS instead."
        elif port == 23:
            risk = "high"
            info += " (Telnet Unencrypted)"
            fix = "CRITICAL: Disable immediately. Use SSH (Port 22)."
        elif port == 3389 or port == 5900:
            risk = "high"
            info += " (Remote Desktop Exposed)"
            fix = "Place behind a VPN or restrict access via Firewall."
        elif port == 80 or port == 8080:
            risk = "medium"
            fix = "Enforce HTTPS (Port 443) with a valid SSL certificate."

    return risk, info, fix

def guess_device_type(host_data, open_ports):
    # Check for Nmap OS match first
    if 'osmatch' in host_data and host_data['osmatch']:
        # Return the highest accuracy match
        best_match = host_data['osmatch'][0]
        if 'name' in best_match:
            return best_match['name']

    # Fallback Heuristics
    if 'vendor' in host_data and host_data['vendor']:
        vendor_name = list(host_data['vendor'].values())[0].lower()
        if "apple" in vendor_name: return "Apple Device"
        if "espressif" in vendor_name: return "Smart Home (IoT)"
    if 53 in open_ports: return "Router/Gateway"   
    
    return "Workstation"

if not target_ip:
    print("[]")
    sys.exit(0)

try:
    nm=nmap.PortScanner()
    output_list=[]
    
    # BASE ARGUMENTS: Standard Service + OS Detection (Optimized for Speed)
    # Removing '--script vuln' by default as it causes extreme delays/timeouts on consumer networks.
    # Re-enable if dedicated "Deep Vulnerability Scan" is requested.
    scan_args = "-sV -O --version-light"
    
    # STEALTH MODE (Predator Protocol)
    # -T2: Slower timing to evade IDS
    # -f: Fragment packets
    # -D RND:5: Send decoys
    if stealth_mode.lower() == "true":
        scan_args += " -T2 -f -D RND:5"
    else:
        scan_args += " -T4 --max-retries 1" # Fast scan with limited retries

    # Execute Scan
    # Note: On Windows, -f/mtu might require Npcap driver support with loopback issues, 
    # but we follow user request for 'all features'.
    scanning=nm.scan(hosts=target_ip, arguments=scan_args)

    for host in nm.all_hosts():
        open_ports_list = []
        vuln_list = []
        
        protocols = nm[host].all_protocols()
        if not protocols: 
            continue

        for proto in protocols:
            for port in (nm[host][proto].keys()): 
                state = nm[host][proto][port]["state"]

                if state == "open":
                    open_ports_list.append(port)
                    service = nm[host][proto][port]["name"]
                    product = nm[host][proto][port].get("product", "")
                    version = nm[host][proto][port].get("version", "")
                    
                    # Extract Script Results (CVEs)
                    cves_found = []
                    script_output = nm[host][proto][port].get("script", {})
                    for script_id, result in script_output.items():
                        cves_found.append(f"[{script_id}] {result.strip()}")

                    risk_status,info_status,fix_status=analyze_risk(port,service, product, version, cves_found)
                    
                    vuln_list.append({
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "risk": risk_status,
                        "info": info_status,
                        "remediation": fix_status,
                        "cves": cves_found # Pass raw CVE list for UI
                    })
        
        device=guess_device_type(nm[host], open_ports_list)
        output_list.append({
            "ip": host,
            "type": device,
            "vulns": vuln_list
        })
    print(json.dumps(output_list))
except Exception as e:
    # Print empty list or error object as JSON so server doesn't fail
    error_response = [{"error": str(e), "ip": target_ip, "type": "Scan Failed", "vulns": []}]
    print(json.dumps(error_response))
