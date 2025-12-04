const scanBtn = document.getElementById('scanBtn');
const deviceList = document.getElementById('deviceList');
const orbitContainer = document.getElementById('orbitContainer');
const detailsPanel = document.getElementById('detailsPanel');
const detailTitle = document.getElementById('detailTitle');
const detailDesc = document.getElementById('detailDesc');

// --- MOCK DATA ---
const mockData = [
    {
        ip: "192.168.1.1",
        type: "Router",
        vulns: [
            { port: 80, service: "HTTP", risk: "low", info: "Standard Web Port" },
            { port: 443, service: "HTTPS", risk: "low", info: "Secure Web Port" }
        ]
    },
    {
        ip: "192.168.1.55",
        type: "Database",
        vulns: [
            { port: 3306, service: "MySQL", risk: "medium", info: "Database Exposed" },
            { port: 22, service: "SSH", risk: "low", info: "Secure Shell" }
        ]
    },
    {
        ip: "192.168.1.102",
        type: "Legacy Server",
        vulns: [
            { port: 23, service: "Telnet", risk: "high", info: "Unencrypted traffic! Exploit likely." },
            { port: 21, service: "FTP", risk: "high", info: "Anonymous Login Allowed" },
            { port: 80, service: "HTTP", risk: "medium", info: "Outdated Apache Version" }
        ]
    }
];

scanBtn.addEventListener('click', startScan);

// REFACTORED: Now using async/await
async function startScan() {
    const ip = document.getElementById('targetIp').value;
    deviceList.innerHTML = '<div class="empty-state">Scanning Network...</div>';

    try {
        // Await the fetch response
        const res = await fetch('http://localhost:3000/ip-send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });

        // Check for HTTP errors (like 404 or 500)
        if (!res.ok) {
            throw new Error(`Server Error: ${res.status}`);
        }

        // Await the JSON parsing
        const data = await res.json();
        
        // Success! Render data
        renderDeviceList(data);

    } catch (err) {
        // Handle errors (Network fail, Python crash, etc.)
        console.error("Scan Failed, switching to mock data:", err);
        
        // Use timeout to simulate a slight delay before showing fallback
        setTimeout(() => {
            renderDeviceList(mockData);
        }, 1000);
    }
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

        card.innerHTML = `
            <div class="card-icon" style="color: ${color}">
                <i class="fa-solid fa-${device.type === 'Router' ? 'wifi' : 'server'}"></i>
            </div>
            <div class="card-info">
                <h4>${device.ip}</h4>
                <p>${vulnCount} Services | ${riskCount} Critical</p>
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
            
            if(vuln.risk === 'high') detailTitle.style.color = '#ef4444';
            else if(vuln.risk === 'medium') detailTitle.style.color = '#f59e0b';
            else detailTitle.style.color = '#10b981';
            
            detailDesc.innerText = vuln.info;
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