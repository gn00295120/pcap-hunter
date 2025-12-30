#!/usr/bin/env python3
"""Test Phase 4 with malicious beacon PCAP."""

from playwright.sync_api import sync_playwright
import time

PCAP_PATH = "/Users/longweiwang/github/pcap-hunter/samples/malicious/synthetic_beacon.pcap"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 1000})

        print("1. Opening app...")
        page.goto('http://localhost:8503')
        page.wait_for_load_state('networkidle')
        time.sleep(3)

        print("2. Uploading malicious beacon PCAP...")
        file_input = page.locator('input[type="file"]')
        file_input.set_input_files(PCAP_PATH)
        time.sleep(2)
        print(f"   Uploaded: {PCAP_PATH}")

        print("3. Starting analysis...")
        analyze_btn = page.locator('button:has-text("Extract & Analyze")')
        analyze_btn.click()

        # Wait for analysis
        print("4. Waiting for analysis (may take 30-60s)...")
        for i in range(60):
            time.sleep(2)
            content = page.content()
            if "Showing all" in content and "0 flows" not in content:
                import re
                match = re.search(r'Showing all (\d+) flows', content)
                if match:
                    print(f"   Analysis done! {match.group(1)} flows")
                    break
            if i % 10 == 0:
                print(f"   Processing... ({i*2}s)")

        time.sleep(3)

        # Screenshot upload result
        page.screenshot(path='/tmp/threat_upload.png', full_page=True)
        print("   Saved: /tmp/threat_upload.png")

        # Go to Dashboard
        print("\n5. Opening Dashboard...")
        page.locator('button:has-text("Dashboard")').click()
        time.sleep(3)

        # Full page screenshot
        page.screenshot(path='/tmp/threat_dashboard.png', full_page=True)
        print("   Saved: /tmp/threat_dashboard.png")

        # Check for Phase 4 features
        print("\n6. Checking Phase 4 features...")
        content = page.content().lower()

        features = {
            "MITRE ATT&CK": "mitre" in content or "att&ck" in content or "t1071" in content,
            "Beacon Detection": "beacon" in content,
            "IOC Scores": "priority" in content and "score" in content,
            "Attack Narrative": "narrative" in content,
            "IOC Export": "export" in content and ("stix" in content or "csv" in content),
        }

        for name, found in features.items():
            status = "FOUND" if found else "not visible"
            print(f"   {name}: {status}")

        # Scroll and capture more
        print("\n7. Capturing all sections...")
        for i in range(5):
            page.evaluate(f"window.scrollTo(0, {i * 600})")
            time.sleep(0.5)
            page.screenshot(path=f'/tmp/threat_scroll_{i}.png')

        print("   Saved 5 scrolled screenshots")

        browser.close()
        print("\nDone!")

if __name__ == "__main__":
    main()
