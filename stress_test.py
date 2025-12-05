import urllib.request
import urllib.error
import json
import time
import datetime

SERVER_URL = "http://localhost:3000"
RESULTS_FILE = "stress_test_results.json"

def get_gateway():
    try:
        with urllib.request.urlopen(f"{SERVER_URL}/gateway") as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                return data.get("ip")
    except Exception as e:
        print(f"Error fetching gateway: {e}")
    return None

def run_stress_test():
    gateway_ip = get_gateway()
    if not gateway_ip:
        print("Could not detect gateway. Aborting stress test.")
        return

    print(f"Starting stress test on Gateway: {gateway_ip}")
    results = []

    for i in range(1, 21):
        print(f"Run {i}/20...", end="", flush=True)
        start_time = time.time()
        
        try:
            req = urllib.request.Request(
                f"{SERVER_URL}/ip-send", 
                data=json.dumps({"ip": gateway_ip}).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req) as response:
                duration = time.time() - start_time
                status = "SUCCESS"
                data = json.loads(response.read().decode())
                
                print(f" {status} ({duration:.2f}s)")
                
                results.append({
                    "run": i,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "status": status,
                    "duration_seconds": duration,
                    "data": data
                })

        except urllib.error.HTTPError as e:
            duration = time.time() - start_time
            print(f" FAILED: {e.code} ({duration:.2f}s)")
            results.append({
                "run": i,
                "timestamp": datetime.datetime.now().isoformat(),
                "status": "FAILED",
                "error": f"HTTP {e.code}: {e.reason}"
            })
        except Exception as e:
            print(f" ERROR: {e}")
            results.append({
                "run": i,
                "timestamp": datetime.datetime.now().isoformat(),
                "status": "ERROR",
                "error": str(e)
            })
        
        # Small delay
        time.sleep(1)

    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nStress test complete. Results saved to {RESULTS_FILE}")

if __name__ == "__main__":
    run_stress_test()
