const scanBtn = document.getElementById('scanBtn');
const deviceList = document.getElementById('deviceList');
const orbitContainer = document.getElementById('orbitContainer');
const detailsPanel = document.getElementById('detailsPanel');
const detailTitle = document.getElementById('detailTitle');
const detailDesc = document.getElementById('detailDesc');

let currentDeviceData = [];
let networkChart = null;
let networkGraph = null;

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

// Switch View Function
function switchView(viewName) {
    const orbit = document.getElementById('orbitContainer');
    const matrix = document.getElementById('neuralMatrix');

    if (viewName === 'orbit') {
        orbit.classList.remove('hidden');
        matrix.classList.add('hidden');
    } else {
        orbit.classList.add('hidden');
        matrix.classList.remove('hidden');
        renderTopology(currentDeviceData); // Redraw to size correctly
    }
}
window.switchView = switchView; // Expose to global

async function startScan(targetOverride = null) {
    let ip = targetOverride;

    // If targetOverride is not a string (e.g. event object), get input value
    if (typeof ip !== 'string') {
        ip = document.getElementById('targetIp').value;
    }

    const stealth = document.getElementById('stealthMode').checked;

    deviceList.innerHTML = '<div class="empty-state">Scanning Network...</div>';

    // DEMO MODE logic
    if (document.getElementById('demoMode').checked) {
        setTimeout(() => {
            currentDeviceData = mockData;
            renderDeviceList(mockData);
            renderTopology(mockData);
        }, 1000);
        return;
    }

    try {
        const res = await fetch('http://localhost:3000/ip-send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip: ip,
                stealthMode: stealth // Prime Feature
            })
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || `Server Error: ${res.status}`);
        }

        const data = await res.json();

        // Handle Drift Alert
        if (data.drift) {
            alert(`⚠️ SECURITY DRIFT DETECTED: ${data.drift.message}`);
        }

        currentDeviceData = data.results || data; // Handle wrapper or direct array
        renderDeviceList(currentDeviceData);
        renderTopology(currentDeviceData);

        // Auto-Notify AI Agent
        if (currentDeviceData && currentDeviceData.length > 0) {
            notifyAgentOnScan(currentDeviceData[0]);
        }

    } catch (err) {
        console.error("Scan Failed:", err);
        deviceList.innerHTML = `<div class="empty-state" style="color: #ef4444;">Scan Failed:<br>${err.message}</div>`;
    }
}

// --- VIS.JS TOPOLOGY (Neural Matrix) ---
function renderTopology(devices) {
    const container = document.getElementById('neuralMatrix');
    if (!devices || devices.length === 0) return;

    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();

    // Central Node (Gateway/Scanner)
    nodes.add({ id: 0, label: 'Sentinel', color: '#6366f1', size: 30, shape: 'dot' });

    devices.forEach((device, index) => {
        const devId = index + 1;

        // Color based on risk
        let color = '#10b981';
        const riskHigh = device.vulns ? device.vulns.some(v => v.risk === 'high') : false;
        if (riskHigh) color = '#ef4444';

        nodes.add({
            id: devId,
            label: `${device.type}\n${device.ip}`,
            color: color,
            shape: 'dot',
            size: 20
        });

        edges.add({ from: 0, to: devId, color: { color: '#444' } });

        // Add Ports as child nodes
        if (device.vulns) {
            device.vulns.forEach((v, vIndex) => {
                const portId = `${devId}-${v.port}`;
                let portColor = '#10b981';
                if (v.risk === 'medium') portColor = '#f59e0b';
                if (v.risk === 'high') portColor = '#ef4444';

                nodes.add({
                    id: portId,
                    label: `${v.port}`,
                    color: portColor,
                    shape: 'dot',
                    size: 10
                });

                edges.add({ from: devId, to: portId, length: 50, color: { color: '#333', opacity: 0.5 } });
            });
        }
    });

    const data = { nodes, edges };
    const options = {
        nodes: {
            font: { color: '#fff' }
        },
        physics: {
            stabilization: false,
            barnesHut: { gravitationalConstant: -2000, springConstant: 0.04 }
        },
        layout: {
            improvedLayout: true
        }
    };

    if (networkGraph) {
        networkGraph.setData(data);
    } else {
        networkGraph = new vis.Network(container, data, options);
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

function renderChart(devices) {
    const statsPanel = document.getElementById('statsPanel');
    if (!devices || devices.length === 0) {
        statsPanel.classList.add('hidden');
        return;
    }
    statsPanel.classList.remove('hidden');

    const ctx = document.getElementById('networkChart').getContext('2d');

    // Aggregate Device Types
    const typeCounts = {};
    devices.forEach(d => {
        typeCounts[d.type] = (typeCounts[d.type] || 0) + 1;
    });

    const labels = Object.keys(typeCounts);
    const data = Object.values(typeCounts);

    if (networkChart) {
        networkChart.destroy();
    }

    networkChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#6366f1', '#10b981', '#ef4444', '#f59e0b', '#ec4899'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#ccc', font: { size: 10 } }
                }
            }
        }
    });
}

function renderDeviceList(devices) {
    deviceList.innerHTML = '';

    // Update Chart
    renderChart(devices);

    if (!devices || devices.length === 0) {
        deviceList.innerHTML = '<div class="empty-state">No devices found.</div>';
        return;
    }

    devices.forEach((device, index) => {
        const card = document.createElement('div');
        card.className = 'device-card';

        const riskCount = device.vulns ? device.vulns.filter(v => v.risk === 'high').length : 0;
        const color = riskCount > 0 ? '#ef4444' : '#10b981';

        // FIX: Added the Security Score Badge here
        const score = calculateSecurityScore(device);
        let scoreColor = '#10b981'; // Green
        if (score < 50) scoreColor = '#ef4444'; // Red
        else if (score < 80) scoreColor = '#f59e0b'; // Orange

        card.innerHTML = `
            <div class="card-icon" style="color: ${color}">
                <i class="fa-solid fa-${device.type === 'Router' ? 'wifi' : 'server'}"></i>
            </div>
            <div class="card-info">
                <h4>${device.ip}</h4>
                <p>Type: ${device.type}</p>
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

    if (!device.vulns) return;

    const sortedVulns = device.vulns.sort((a, b) => {
        const priority = { 'high': 3, 'medium': 2, 'low': 1 };
        return priority[b.risk] - priority[a.risk];
    });

    const totalVulns = sortedVulns.length;
    const angleStep = (2 * Math.PI) / totalVulns;

    sortedVulns.forEach((vuln, index) => {
        const angle = index * angleStep;
        let radius = 220;
        if (vuln.risk === 'high') radius = 140;
        if (vuln.risk === 'medium') radius = 180;

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

            // Format CVEs if present
            let cveHtml = "";
            if (vuln.cves && vuln.cves.length > 0) {
                cveHtml = `<div style="margin-top: 5px; color: #ff9999; font-size: 0.85em;">
                            <strong>⚠️ Vulnerabilities:</strong><br>
                            ${vuln.cves.slice(0, 3).join("<br>")}
                           </div>`;
            }

            detailDesc.innerHTML = `
                <strong>Analysis:</strong> ${vuln.info} <br>
                ${cveHtml}
                <br>
                <strong>🛡️ Recommended Fix:</strong> <br> ${vuln.remediation || "No specific fix."}
            `;

            if (vuln.risk === 'high') detailTitle.style.color = '#ef4444';
            else if (vuln.risk === 'medium') detailTitle.style.color = '#f59e0b';
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
if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
        if (!window.jspdf) {
            alert("PDF Library not loaded!");
            return;
        }
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        doc.setFontSize(22);
        doc.setTextColor(99, 102, 241); // Indigo
        doc.text("Net-Sentinel: Guardian Report", 10, 15);

        doc.setFontSize(10);
        doc.setTextColor(100);
        doc.text(`Generated: ${new Date().toLocaleString()}`, 10, 22);
        doc.line(10, 25, 200, 25);

        let yPos = 35;

        if (currentDeviceData.length === 0) {
            doc.text("No scan data available.", 10, 35);
        } else {
            currentDeviceData.forEach(device => {
                doc.setFontSize(16);
                doc.setTextColor(0, 0, 0);
                doc.text(`Device: ${device.ip} (${device.type})`, 10, yPos);

                // Security Score
                const score = calculateSecurityScore(device);
                doc.setFontSize(12);
                doc.setTextColor(score < 50 ? 255 : 0, score < 50 ? 0 : 0, 0);
                doc.text(`Security Score: ${score}/100`, 150, yPos);

                yPos += 10;

                doc.setFontSize(10);
                if (device.vulns) {
                    device.vulns.forEach(v => {
                        // Color code the PDF text
                        if (v.risk === 'high') doc.setTextColor(220, 20, 60);
                        else if (v.risk === 'medium') doc.setTextColor(255, 140, 0);
                        else doc.setTextColor(0, 128, 0);

                        doc.text(` • [${v.risk.toUpperCase()}] Port ${v.port}: ${v.service}`, 15, yPos);
                        yPos += 6;

                        if (v.cves && v.cves.length > 0) {
                            doc.setTextColor(100, 0, 0);
                            doc.setFontSize(8);
                            v.cves.slice(0, 3).forEach(cve => {
                                doc.text(`    ${cve}`, 20, yPos);
                                yPos += 4;
                            });
                            doc.setFontSize(10);
                        }

                        // Add fix in black
                        doc.setTextColor(60, 60, 60);
                        doc.text(`    Fix: ${v.remediation || "N/A"}`, 20, yPos);
                        yPos += 8;

                        // Check page break
                        if (yPos > 270) {
                            doc.addPage();
                            yPos = 20;
                        }
                    });
                }
                yPos += 15;

                // Add page if too long
                if (yPos > 270) {
                    doc.addPage();
                    yPos = 20;
                }
            });
        }

        doc.save("net-sentinel-guardian-report.pdf");
    });
}

// --- SENTINEL AGENTIC AI ---
let chatHistory = [];
const terminal = document.getElementById('sentinelTerminal');
const chatBody = document.getElementById('chatHistory');
const chatInput = document.getElementById('chatInput');

function toggleTerminal(forceOpen = null) {
    if (forceOpen === true) {
        terminal.classList.add('expanded');
    } else if (forceOpen === false) {
        terminal.classList.remove('expanded');
    } else {
        terminal.classList.toggle('expanded');
    }
}

function handleChatKey(e) {
    if (e.key === 'Enter') sendChat();
}

function appendMessage(role, text) {
    const div = document.createElement('div');
    div.className = role === 'user' ? 'msg-user' : 'msg-sentinel';

    // Simple markdown-ish bolding
    const formatted = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    div.innerHTML = formatted;

    chatBody.appendChild(div);
    chatBody.scrollTop = chatBody.scrollHeight;

    // Add to history state
    chatHistory.push({ role: role === 'user' ? 'user' : 'model', text: text });
}

async function sendChat() {
    const text = chatInput.value.trim();
    if (!text) return;

    appendMessage('user', text);
    chatInput.value = '';

    // Show typing indicator
    const typingId = 'typing-' + Date.now();
    const typingDiv = document.createElement('div');
    typingDiv.id = typingId;
    typingDiv.className = 'msg-sentinel';
    typingDiv.style.fontStyle = 'italic';
    typingDiv.innerText = 'Analyzing...';
    chatBody.appendChild(typingDiv);

    try {
        const targetDevice = currentDeviceData.length > 0 ? currentDeviceData[0] : null;

        const res = await fetch('http://localhost:3000/ai-chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: text,
                history: chatHistory.slice(0, -1), // Send history excluding just added user msg (handled by backend logic often, but here we just pass it)
                scanContext: targetDevice
            })
        });

        const data = await res.json();

        // Remove typing
        const tDiv = document.getElementById(typingId);
        if (tDiv) tDiv.remove();

        if (data.reply) {
            appendMessage('sentinel', data.reply);
        } else {
            appendMessage('sentinel', "Connection error. Sentinel offline.");
        }

    } catch (err) {
        document.getElementById(typingId)?.remove();
        appendMessage('sentinel', "Error connecting to Sentinel Core.");
        console.error(err);
    }
}

// Auto-notify Agent on Scan Complete
function notifyAgentOnScan(device) {
    const vulnCount = device.vulns ? device.vulns.length : 0;
    const highRisk = device.vulns ? device.vulns.filter(v => v.risk === 'high').length : 0;

    let msg = `Scan complete for **${device.ip}** (${device.type}). Found **${vulnCount}** open ports with **${highRisk}** high risk issues.`;
    if (highRisk > 0) msg += " Immediate attention required.";

    appendMessage('sentinel', msg);
    toggleTerminal(true); // Auto-open terminal
}

// Attach Event Listeners
scanBtn.addEventListener('click', () => startScan());
document.getElementById('targetIp').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') startScan();
});