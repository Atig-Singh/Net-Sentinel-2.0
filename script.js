const scanBtn = document.getElementById('scanBtn');
const deviceList = document.getElementById('deviceList');
const orbitContainer = document.getElementById('orbitContainer');
const detailsPanel = document.getElementById('detailsPanel');
const detailTitle = document.getElementById('detailTitle');
const detailDesc = document.getElementById('detailDesc');

let currentDeviceData = [];

// --- MOCK DATA ---
const mockData = [
    {
        ip: "192.168.1.1",
        type: "Router",
        vulns: [
            { port: 80, service: "HTTP", risk: "low", info: "Standard Web Port", remediation: "Ensure firmware is updated." },
            { port: 443, service: "HTTPS", risk: "low", info: "Secure Web Port", remediation: "None." }
        ]
    },
    {
        ip: "192.168.1.55",
        type: "Database",
        vulns: [
            { port: 3306, service: "MySQL", risk: "medium", info: "Database Exposed", remediation: "Restrict IP access to localhost." },
            { port: 22, service: "SSH", risk: "low", info: "Secure Shell", remediation: "Use key-based auth." }
        ]
    },
    {
        ip: "192.168.1.102",
        type: "Legacy Server",
        vulns: [
            { port: 23, service: "Telnet", risk: "high", info: "Unencrypted traffic!", remediation: "DISABLE IMMEDIATELY. Use SSH." },
            { port: 21, service: "FTP", risk: "high", info: "Anonymous Login", remediation: "Disable anonymous login or use SFTP." },
            { port: 80, service: "HTTP", risk: "medium", info: "Outdated Apache", remediation: "Update Apache to latest version." }
        ]
    }
];

scanBtn.addEventListener('click', startScan);

async function startScan() {
    const ip = document.getElementById('targetIp').value;
    deviceList.innerHTML = '<div class="empty-state">Scanning Network...</div>';

    try {
        const res = await fetch('http://localhost:3000/ip-send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });

        if (!res.ok) {
            throw new Error(`Server Error: ${res.status}`);
        }

        const data = await res.json();
        
        // FIX: Save data to global variable for the PDF report
        currentDeviceData = data;
        
        renderDeviceList(data);

    } catch (err) {
        console.error("Scan Failed, switching to mock data:", err);
        
        setTimeout(() => {
            // FIX: Save mock data to global variable too
            currentDeviceData = mockData;
            renderDeviceList(mockData);
        }, 1000);
    }
}

function calculateSecurityScore(device) {
    let score = 100;
    // Safety check if vulns is undefined
    if (!device.vulns) return score;

    const highRisks = device.vulns.filter(v => v.risk === 'high').length;
    const medRisks = device.vulns.filter(v => v.risk === 'medium').length;
    
    score -= (highRisks * 20); 
    score -= (medRisks * 10); 
    
    if (score < 0) score = 0;
    return score;
}

function renderDeviceList(devices) {
    deviceList.innerHTML = '';
    
    if(devices.length === 0) {
        deviceList.innerHTML = '<div class="empty-state">No devices found.</div>';
        return;
    }

    devices.forEach((device, index) => {
        const card = document.createElement('div');
        card.className = 'device-card';
        
        const riskCount = device.vulns ? device.vulns.filter(v => v.risk === 'high').length : 0;
        const color = riskCount > 0 ? '#ef4444' : '#10b981';
        const vulnCount = device.vulns ? device.vulns.length : 0;
        
        // FIX: Added the Security Score Badge here
        const score = calculateSecurityScore(device);
        let scoreColor = '#10b981'; // Green
        if(score < 50) scoreColor = '#ef4444'; // Red
        else if(score < 80) scoreColor = '#f59e0b'; // Orange

        card.innerHTML = `
            <div class="card-icon" style="color: ${color}">
                <i class="fa-solid fa-${device.type === 'Router' ? 'wifi' : 'server'}"></i>
            </div>
            <div class="card-info">
                <h4>${device.ip}</h4>
                <p>${vulnCount} Services | ${riskCount} Critical</p>
                <div style="font-size: 10px; margin-top: 5px; color: ${scoreColor}; font-weight: bold;">
                    Security Score: ${score}/100
                </div>
            </div>
        `;

        card.addEventListener('click', () => {
            document.querySelectorAll('.device-card').forEach(c => c.classList.remove('active'));
            card.classList.add('active');
            renderOrbitSystem(device);
        });

        deviceList.appendChild(card);
    });
}

function renderOrbitSystem(device) {
    orbitContainer.innerHTML = ''; 
    detailsPanel.classList.add('hidden');

    const core = document.createElement('div');
    core.className = 'core-node';
    core.innerHTML = `
        <i class="fa-solid fa-${device.type === 'Router' ? 'wifi' : 'server'}"></i>
        <span>${device.ip}</span>
    `;
    orbitContainer.appendChild(core);

    if(!device.vulns) return;

    const sortedVulns = device.vulns.sort((a, b) => {
        const priority = { 'high': 3, 'medium': 2, 'low': 1 };
        return priority[b.risk] - priority[a.risk];
    });

    const totalVulns = sortedVulns.length;
    const angleStep = (2 * Math.PI) / totalVulns;

    sortedVulns.forEach((vuln, index) => {
        const angle = index * angleStep;
        let radius = 220;
        if(vuln.risk === 'high') radius = 140;
        if(vuln.risk === 'medium') radius = 180;

        const x = Math.cos(angle) * radius;
        const y = Math.sin(angle) * radius;

        const vulnNode = document.createElement('div');
        vulnNode.className = `vuln-node risk-${vuln.risk}`;
        
        vulnNode.style.left = '50%';
        vulnNode.style.top = '50%';
        vulnNode.style.marginTop = '-30px'; 
        vulnNode.style.marginLeft = '-30px';
        
        vulnNode.style.transform = `translate(${x}px, ${y}px)`;
        vulnNode.innerHTML = `<span>${vuln.port}</span>`;

        vulnNode.addEventListener('mouseenter', () => {
            detailsPanel.classList.remove('hidden');
            detailTitle.innerText = `Port ${vuln.port} (${vuln.service})`;
            
            // FIX: Removed the line that was overwriting the HTML
            detailDesc.innerHTML = `
                <strong>Analysis:</strong> ${vuln.info} <br><br>
                <strong>🛡️ Recommended Fix:</strong> <br> ${vuln.remediation || "No specific fix."}
            `;
            
            if(vuln.risk === 'high') detailTitle.style.color = '#ef4444';
            else if(vuln.risk === 'medium') detailTitle.style.color = '#f59e0b';
            else detailTitle.style.color = '#10b981';
        });

        orbitContainer.appendChild(vulnNode);
    });

    addRing(140);
    addRing(180);
    addRing(220);
}

function addRing(size) {
    const ring = document.createElement('div');
    ring.className = 'ring';
    ring.style.width = (size * 2) + 'px';
    ring.style.height = (size * 2) + 'px';
    ring.style.left = '50%';
    ring.style.top = '50%';
    ring.style.transform = 'translate(-50%, -50%)'; 
    orbitContainer.appendChild(ring);
}

const downloadBtn = document.getElementById('downloadBtn');
if(downloadBtn) {
    downloadBtn.addEventListener('click', () => {
        if (!window.jspdf) {
            alert("PDF Library not loaded!");
            return;
        }
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        doc.setFontSize(20);
        doc.text("Net-Sentinel Security Report", 10, 10);
        
        let yPos = 30;
        
        if(currentDeviceData.length === 0) {
            doc.text("No scan data available.", 10, 30);
        } else {
            currentDeviceData.forEach(device => {
                doc.setFontSize(14);
                doc.setTextColor(0, 0, 0);
                doc.text(`Device: ${device.ip} (${device.type}) - Score: ${calculateSecurityScore(device)}`, 10, yPos);
                yPos += 10;
                
                doc.setFontSize(10);
                if(device.vulns) {
                    device.vulns.forEach(v => {
                        // Color code the PDF text
                        if(v.risk === 'high') doc.setTextColor(255, 0, 0);
                        else if(v.risk === 'medium') doc.setTextColor(255, 165, 0);
                        else doc.setTextColor(0, 128, 0);

                        doc.text(` - [${v.risk.toUpperCase()}] Port ${v.port}: ${v.service}`, 15, yPos);
                        yPos += 7;
                        
                        // Add fix in black
                        doc.setTextColor(50, 50, 50);
                        doc.text(`   Fix: ${v.remediation || "N/A"}`, 15, yPos);
                        yPos += 10;
                    });
                }
                yPos += 10; 
                
                // Add page if too long
                if(yPos > 280) {
                    doc.addPage();
                    yPos = 20;
                }
            });
        }
        
        doc.save("net-sentinel-report.pdf");
    });
}

const aiBtn = document.getElementById('aiBtn');
const aiModal = document.getElementById('aiModal');
const aiText = document.getElementById('aiText');
const aiLoader = document.getElementById('aiLoader');
const closeModal = document.querySelector('.close-modal');
closeModal.onclick = () => aiModal.classList.add('hidden');
window.onclick = (e) => { if(e.target == aiModal) aiModal.classList.add('hidden'); }

aiBtn.addEventListener('click', async () => {
    if(!currentDeviceData || currentDeviceData.length === 0) {
        alert("Please scan a target first!");
        return;
    }
    
    const targetDevice = currentDeviceData[0]; // Analyze the first device

    // 2. Open Modal & Show Loader
    aiModal.classList.remove('hidden');
    aiText.innerText = "";
    aiLoader.classList.remove('hidden');

    try {
        // 3. Call Node Server
        const res = await fetch('http://localhost:3000/ai-analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scanData: targetDevice })
        });

        const data = await res.json();

        // 4. Show Result
        aiLoader.classList.add('hidden');
        typeWriterEffect(data.analysis || data.error);

    } catch (err) {
        aiLoader.classList.add('hidden');
        aiText.innerText = "Error contacting AI Analyst.";
    }
});
function typeWriterEffect(text) {
    let i = 0;
    aiText.innerHTML = "";
    const speed = 20; 
    
    function type() {
        if (i < text.length) {
            aiText.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    type();
}