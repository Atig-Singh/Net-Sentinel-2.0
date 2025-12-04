import express from "express";
import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv"
dotenv.config()

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static('public'));
app.use(cors());

app.post("/ip-send", async (req, res) => {
    const ip = req.body.ip;

    if (!ip) {
        return res.status(400).json({ error: "No IP provided" });
    }

    const scriptPath = path.join(__dirname, 'scanner.py');
    console.log(`[Node] Target: ${ip}`);

    try {
        const dataString = await new Promise((resolve, reject) => {
            const python = spawn('python', ['-u', scriptPath, ip]);
            let output = '';

            python.stdout.on('data', (data) => {
                output += data.toString();
            });

            python.stderr.on('data', (data) => {
                console.error(`[Python Error] ${data.toString()}`);
            });

            python.on('error', (err) => {
                reject(err);
            });

            python.on('close', (code) => {
                resolve(output);
            });
        });
        if (!dataString.trim()) {
            throw new Error("Python returned empty result");
        }
        const jsonResults = JSON.parse(dataString);
        res.json(jsonResults);

    } catch (error) {
        console.error("Scan Error:", error);
        res.json([]); 
    }
});

const genAI = new GoogleGenerativeAI(process.env.API_KEY);

app.post("/ai-analyze", async (req, res) => {
    const scanData = req.body.scanData;

    if (!scanData) {
        return res.status(400).json({ error: "No scan data provided" });
    }

    try {
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-pro" });
        const prompt = `
        Act as a Senior Cybersecurity Analyst. 
        I have scanned a device with IP: ${scanData.ip} (${scanData.type}).
        
        Here are the open ports and risks found:
        ${JSON.stringify(scanData.vulns)}
        
        Please provide a short, professional executive summary (max 3 sentences) explaining how dangerous this device is.
        Then, provide a bulleted list of 3 specific, technical steps to secure it.
        Do not use markdown formatting like ** or ##, just plain text.
        `;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();

        res.json({ analysis: text });

    } catch (error) {
        console.error("AI Error:", error);
        res.status(500).json({ error: "AI Analyst is currently unavailable." });
    }
});
app.listen(port, () => {
    console.log(`Server running at PORT:${port}`);
});