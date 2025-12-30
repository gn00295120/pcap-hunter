#!/usr/bin/env python3
"""Capture full pages with proper viewport."""

from playwright.sync_api import sync_playwright
import time

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Use very tall viewport to capture everything
        page = browser.new_page(viewport={"width": 1400, "height": 4000})

        print("1. Opening app...")
        page.goto('http://localhost:8503')
        page.wait_for_load_state('networkidle')
        time.sleep(3)

        # Dashboard should still have data
        print("2. Checking Dashboard...")
        page.locator('button:has-text("Dashboard")').click()
        time.sleep(3)

        # Full page screenshot
        page.screenshot(path='/tmp/full_dashboard.png', full_page=True)
        print("   Saved: /tmp/full_dashboard.png")

        # Check Upload page for analysis results
        print("\n3. Checking Upload page...")
        page.locator('button:has-text("Upload")').click()
        time.sleep(2)
        page.screenshot(path='/tmp/full_upload.png', full_page=True)
        print("   Saved: /tmp/full_upload.png")

        # Check Progress page
        print("\n4. Checking Progress page...")
        page.locator('button:has-text("Progress")').click()
        time.sleep(2)
        page.screenshot(path='/tmp/full_progress.png', full_page=True)
        print("   Saved: /tmp/full_progress.png")

        # Print what's in DOM
        print("\n5. Searching for Phase 4 elements...")
        content = page.content()

        keywords = ["beacon", "mitre", "att&ck", "ioc", "narrative", "priority", "score", "technique"]
        for kw in keywords:
            if kw in content.lower():
                print(f"   FOUND: {kw}")

        browser.close()
        print("\nDone!")

if __name__ == "__main__":
    main()
