import express from "express";
import { spawn, execSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv"
import os from "os";
import fs from "fs";

dotenv.config()

// Check if nmap is available
try {
    execSync("nmap --version", { stdio: "ignore" });
} catch (e) {
    console.warn("WARNING: 'nmap' is not installed or not in PATH. Scanning will fail.");
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static('public'));
app.use(cors());

// Helper to calculate CIDR
function getCIDR(ip, netmask) {
    const subnetMask = netmask.split('.').map(Number);
    let cidr = 0;
    for (const part of subnetMask) {
        cidr += (part >>> 0).toString(2).split('1').length - 1;
    }

    // Calculate Base IP
    const ipParts = ip.split('.').map(Number);
    const maskParts = netmask.split('.').map(Number);
    const baseIpParts = ipParts.map((part, i) => part & maskParts[i]);
    const baseIp = baseIpParts.join('.');

    return `${baseIp}/${cidr}`;
}

function getDefaultGateway() {
    const platform = os.platform();
    try {
        if (platform === 'win32') {
            const output = execSync("ipconfig", { encoding: "utf-8" });
            const lines = output.split("\n");
            let foundGatewaySection = false;

            for (const line of lines) {
                if (line.includes("Default Gateway")) {
                    foundGatewaySection = true;
                }
                if (foundGatewaySection) {
                    const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
                    if (ipMatch) {
                        return ipMatch[1];
                    }
                }
                if (line.trim().length > 0 && !line.startsWith(" ") && !line.includes("Default Gateway")) {
                    foundGatewaySection = false;
                }
            }
        } else if (platform === 'linux' || platform === 'darwin') {
            // Linux/macOS support
            try {
                // Try 'ip route' first (Linux standard)
                const output = execSync("ip route | grep default", { encoding: "utf-8" });
                const parts = output.split(/\s+/);
                // Output often looks like: "default via 192.168.1.1 dev eth0"
                const viaIndex = parts.indexOf("via");
                if (viaIndex !== -1 && parts[viaIndex + 1]) {
                    return parts[viaIndex + 1];
                }
            } catch (e1) {
                // Fallback to netstat (macOS/BSD/Legacy Linux)
                const output = execSync("netstat -rn | grep default", { encoding: "utf-8" });
                const parts = output.split(/\s+/);
                // macOS: "default        192.168.1.1        UGSc           en0"
                if (parts[1]) { // Gateway is usually the second column
                    // Basic IP validation to be safe
                    if (/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.test(parts[1])) {
                        return parts[1];
                    }
                }
            }
        }
    } catch (e) {
        console.error("Error finding gateway:", e);
    }
    return null;
}

app.get("/gateway", (req, res) => {
    const gateway = getDefaultGateway();
    if (gateway) {
        res.json({ ip: gateway });
    } else {
        res.status(404).json({ error: "Gateway not found" });
    }
});

app.get("/interfaces", (req, res) => {
    const interfaces = os.networkInterfaces();
    const results = [];

    for (const name of Object.keys(interfaces)) {
        for (const net of interfaces[name]) {
            // Skip internal (loopback) and non-IPv4 addresses
            if (net.family === 'IPv4' && !net.internal) {
                results.push({
                    name: name,
                    ip: net.address,
                    netmask: net.netmask,
                    mac: net.mac,
                    cidr: getCIDR(net.address, net.netmask)
                });
            }
        }
    }
    res.json(results);
});

app.post("/ip-send", async (req, res) => {
    const ip = req.body.ip;
    const stealthMode = req.body.stealthMode || false; // New Prime Feature
    const platform = os.platform();

    if (!ip) {
        return res.status(400).json({ error: "No IP provided" });
    }

    // Basic IP validation (IPv4) or CIDR
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[12]?[0-9]))?$/;
    if (!ipRegex.test(ip) && ip !== "localhost") {
        return res.status(400).json({ error: "Invalid IP address or CIDR format" });
    }

    const scriptPath = path.join(__dirname, 'scanner.py');
    console.log(`[Node] Prime Scan Target: ${ip}, Stealth: ${stealthMode}`);

    // Determine python command
    let pythonCmd = 'python';
    if (platform !== 'win32') {
        try {
            execSync('python3 --version', { stdio: 'ignore' });
            pythonCmd = 'python3';
        } catch (e) {
            // Fallback to python
        }
    }

    try {
        const dataString = await new Promise((resolve, reject) => {
            // Updated ARGS: Pass stealthMode string
            const args = ['-u', scriptPath, ip, String(stealthMode)];

            const python = spawn(pythonCmd, args);
            let output = '';
            let errorOutput = '';

            python.stdout.on('data', (data) => {
                output += data.toString();
            });

            python.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });

            python.on('error', (err) => {
                reject(err);
            });

            python.on('close', (code) => {
                if (code !== 0) {
                    console.warn(`[Python] Process exited with code ${code}. Stderr: ${errorOutput}`);
                }
                resolve(output);
            });
        });

        // Robust JSON extraction
        const jsonMatch = dataString.match(/\[.*\]/s);
        if (!jsonMatch) {
            throw new Error("No valid JSON output found from scanner. Output: " + dataString.substring(0, 200) + "...");
        }

        const jsonResults = JSON.parse(jsonMatch[0]);

        // --- DRIFT DETECTION (Timeline Sentinel) ---
        let driftAlert = null;
        try {
            if (fs.existsSync("scan_history.json")) {
                const historyContent = fs.readFileSync("scan_history.json", "utf-8");
                const lines = historyContent.trim().split("\n");
                let lastScanForIp = null;

                for (let i = lines.length - 1; i >= 0; i--) {
                    const line = lines[i].trim().replace(/,$/, ''); // Remove trailing comma
                    if (!line) continue;
                    try {
                        const entry = JSON.parse(line);
                        if (entry.target === ip) {
                            lastScanForIp = entry;
                            break;
                        }
                    } catch (e) { /* ignore parse errors in history */ }
                }

                if (lastScanForIp) {
                    const oldPorts = new Set(lastScanForIp.results[0]?.vulns?.map(v => v.port) || []);
                    const newPorts = new Set(jsonResults[0]?.vulns?.map(v => v.port) || []);

                    const openedPorts = [...newPorts].filter(x => !oldPorts.has(x));

                    if (openedPorts.length > 0) {
                        driftAlert = {
                            type: "DRIFT_DETECTED",
                            message: `Timeline Sentinel: ${openedPorts.length} NEW ports detected since last scan!`,
                            details: openedPorts
                        };
                    }
                }
            }
        } catch (e) {
            console.warn("Drift detection skipped:", e);
        }

        // Save to history file
        const historyEntry = {
            timestamp: new Date().toISOString(),
            target: ip,
            stealth: stealthMode,
            results: jsonResults
        };

        fs.appendFile("scan_history.json", JSON.stringify(historyEntry) + ",\n", (err) => {
            if (err) console.error("Failed to save history:", err);
        });

        res.json({
            results: jsonResults,
            drift: driftAlert
        });

    } catch (error) {
        console.error("Scan Error:", error);
        res.status(500).json({ error: "Scan failed", details: error.message });
    }
});

let genAI;
if (process.env.API_KEY) {
    try {
        genAI = new GoogleGenerativeAI(process.env.API_KEY);
    } catch (e) {
        console.error("Failed to init AI:", e);
    }
} else {
    console.warn("WARNING: API_KEY is missing. AI analysis will be unavailable.");
}

app.post("/ai-chat", async (req, res) => {
    const { message, history, scanContext } = req.body;

    if (!message) {
        return res.status(400).json({ error: "No message provided" });
    }

    if (!genAI) {
        return res.json({ reply: "⚠️ **Sentinel Core Offline**: No API Key detected in system environment. Please add API_KEY to .env file to enable Agentic features." });
    }

    try {
        const systemPrompt = `
        SYSTEM_ROLE: You are "Sentinel", an elite cybersecurity AI agent embedded in the Net-Sentinel Scanner.
        
        YOUR CAPABILITIES:
        - You analyze network scan data.
        - You explain CVEs and risks in simple, professional terms.
        - You provide specific terminal commands to fix issues (e.g. "Run 'sudo ufw deny 23'").
        - You allow the user to ask follow-up questions.

        CURRENT SCAN CONTEXT:
        Target IP: ${scanContext?.ip || "Unknown"}
        Device Type: ${scanContext?.type || "Unknown"}
        Open Ports: ${JSON.stringify(scanContext?.vulns || [])}
        
        INSTRUCTIONS:
        - Be concise. Use bullet points for steps.
        - If the user asks to "Fix it", provide specific commands for the OS (assume Linux/Ubuntu unless specified).
        - Stay in character: Professional, vigilant, helpful.
        `;

        const model = genAI.getGenerativeModel({ model: "gemini-2.5-pro" });

        // Construct the full prompt conversation
        let fullPrompt = systemPrompt + "\n\nCONVERSATION HISTORY:\n";
        if (Array.isArray(history)) {
            history.forEach(msg => {
                fullPrompt += `${msg.role.toUpperCase()}: ${msg.text}\n`;
            });
        }
        fullPrompt += `USER: ${message}\nSENTINEL:`;

        const result = await model.generateContent(fullPrompt);
        const response = await result.response;
        const text = response.text();

        res.json({ reply: text });

    } catch (error) {
        console.error("AI Error:", error);
        res.status(500).json({ error: "Sentinel AI is offline. Check API Key or Connection." });
    }
});

app.listen(port, () => {
    console.log(`Server running at PORT:${port}`);
});