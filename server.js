import express from "express";
import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";

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

app.listen(port, () => {
    console.log(`Server running at PORT:${port}`);
});