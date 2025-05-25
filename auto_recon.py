#!/usr/bin/env python3
"""
Automated Reconnaissance Tool with Consistent Uniqueness Checking
- All uniqueness checks now compare against previous scan's full results
- Maintains original functionality with improved consistency
"""

import os
import subprocess
import shutil
import datetime
from pathlib import Path
import signal
import sys
import json
import re
from threading import Timer

# ========================== CONFIG ==============================
wordlists_dir = Path("/usr/share/wordlists")
subdomain_wordlists = {
    "1": "SecLists/Discovery/DNS/dns-Jhaddix.txt",
    "2": "SecLists/Discovery/DNS/fierce-hostlist.txt",
    "3": "SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    "4": "SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    "5": "SecLists/Discovery/DNS/combined_subdomains.txt",
    "6": "SecLists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt"
}
directory_wordlists = {
    "1": "SecLists/Discovery/Web-Content/common.txt",
    "2": "SecLists/Discovery/Web-Content/quickhits.txt",
    "3": "SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "4": "SecLists/Discovery/Web-Content/raft-medium-directories.txt",
    "5": "SecLists/Discovery/Web-Content/combined_directories.txt"
}

# ========================== UTILITIES ==============================
def print_header(title):
    print("\n" + "=" * 80)
    print(f"[+] {title}")
    print("=" * 80)

def run_command(command, cwd=None):
    print_header(f"Running Command: {command}")
    try:
        process = subprocess.Popen(command, shell=True, cwd=cwd, 
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in iter(process.stdout.readline, b''):
            print(line.decode(), end='')
        process.wait()
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user.")
        process.terminate()
        sys.exit(1)
    return process.returncode

def confirm_step(step_desc):
    while True:
        answer = input(f"\nDo you want to run this step: {step_desc}? [y/n]: ").strip().lower()
        if answer == 'y':
            return True
        elif answer == 'n':
            return False

def get_previous_date_dir(base_path):
    """Find the most recent previous date directory"""
    today = datetime.datetime.now().date()
    dirs = [d for d in base_path.iterdir() 
           if d.is_dir() and re.match(r"\d{4}-\d{2}-\d{2}", d.name)]
    previous_dirs = sorted([d for d in dirs 
                          if datetime.datetime.strptime(d.name, '%Y-%m-%d').date() < today], 
                          reverse=True)
    return previous_dirs[0] if previous_dirs else None

def get_previous_scan_file(current_dir, subpath):
    """Finds the most recent previous scan file matching subpath"""
    prev_dir = get_previous_date_dir(current_dir.parent.parent)
    return (prev_dir / subpath) if prev_dir else None

def handle_unique_items(target_dir,current_items,file_basename):
    
    merged_file = target_dir / file_basename
    unique_file = target_dir / "unique.txt"

    # Write current merged.txt
    with open(merged_file, "w") as f:
        f.write("\n".join(sorted(current_items)))

    # Use existing function to get previous merged.txt path
    previous_merged = get_previous_scan_file(target_dir, file_basename)

    previous_urls = set()
    if previous_merged and previous_merged.exists():
        with open(previous_merged) as f:
            previous_urls = set(line.strip() for line in f if line.strip())

    # Calculate new unique URLs (in current but not in previous)
    diff_items = current_items - previous_urls

    if not diff_items:
        print("[+] No new unique items found")
        with open(unique_file, "w") as f:
            f.write("")  # Create empty unique.txt file
        return

    print(f"[+] Found {len(diff_items)} new unique items")

    # Write unique.txt with the new URLs only
    with open(unique_file, "w") as f:
        f.write("\n".join(sorted(diff_items)))
    print(f"[+] Saved unique items to {unique_file}")

# ========================== MAIN EXECUTION ==============================
if __name__ == "__main__":
    print("\n> Starting Recon Automation on Kali Linux")

    # Get target information from user
    domain = input("\nEnter the target domain (e.g., example.com): ").strip()
    cookie_header = input("Enter Cookie header if needed (or leave blank): ").strip()
    ports_to_scan = input("Enter ports to scan (e.g., 80,443,8080): ").strip() or "80,443"
    
    # Configure execution mode
    approval_mode = input("\nDo you want to manually approve each step before it runs? [y/n]: ").strip().lower() == 'y'

    # ===================== TOOL AND WORDLIST SELECTION =====================
    print("\nSelect subdomain wordlist:")
    for key, val in subdomain_wordlists.items():
        print(f"{key}. {val}")
    subdomain_selected = input("\nEnter numbers (comma-separated if multiple): ").strip().split(',')
    subdomain_selected_paths = [wordlists_dir / subdomain_wordlists[n.strip()] 
                              for n in subdomain_selected if n.strip() in subdomain_wordlists]

    print("\nSelect directory brute-force wordlist:")
    for key, val in directory_wordlists.items():
        print(f"{key}. {val}")
    directory_selected = input("\nEnter numbers (comma-separated if multiple): ").strip().split(',')
    directory_selected_paths = [wordlists_dir / directory_wordlists[n.strip()] 
                              for n in directory_selected if n.strip() in directory_wordlists]

    print("\nSelect which tools to run:")
    print("1. Subdomain Enumeration")
    print("2. Subdomain Verification")
    print("3. Crawling Domains")
    print("4. Port Scanning")
    print("5. URL Gathering & Param Discovery")
    print("6. Directory Bruteforce")
    print("7. Subdomain Bruteforce")
    print("8. Run All")
    tools_to_run = input("\nEnter numbers (e.g., 1,3,5 or 8): ").strip()
    run_all = '8' in tools_to_run
    selected = lambda x: run_all or str(x) in tools_to_run.split(',')

    # ===================== NEW DIRECTORY STRUCTURE SETUP =====================
    now = datetime.datetime.now().strftime('%Y-%m-%d')
    base_dir = Path.cwd() / f"recon-{domain}"
    date_dir = base_dir / now
    
    # Define all directory paths under the date folder
    subdomains_dir = date_dir / "subdomains"
    unfiltered_dir = subdomains_dir / "unfiltered"
    filtered_dir = subdomains_dir / "filtered"
    endpoints_dir = date_dir / "endpoints"
    scan_dir = date_dir / "scan"
    history_dir = date_dir / "history"
    brute_force_dir = date_dir / "Brute_Force" / "directory"
    brute_sub_dir = date_dir / "Brute_Force" / "subdomains"

    # Create all required directories
    for d in [base_dir, date_dir, subdomains_dir, unfiltered_dir, filtered_dir, 
              endpoints_dir, scan_dir, history_dir, brute_force_dir, brute_sub_dir]:
        d.mkdir(parents=True, exist_ok=True)
        print(f"[+] Created directory: {d}")

    # Define important file paths
    filtered_path = filtered_dir / "subfinder_filtered.txt"
    amass_filtered_file = filtered_dir / "amass_filtered.txt"
    final_filtered_file = filtered_dir / f"{domain}_only.txt"

    # ===================== SUBDOMAIN ENUMERATION =====================
    if selected(1) and (not approval_mode or confirm_step("Subdomain Enumeration")):
        os.chdir(unfiltered_dir)
        
        run_command(f"subfinder -d {domain} -all -recursive -timeout 30 -oJ -t 50 -r /opt/resolvers/resolvers.txt -o subfinder_subdomains.json")
        
        try:
            with open("subfinder_subdomains.json") as f:
                data = [json.loads(line) for line in f if line.strip()]
                subdomains = [entry['host'] for entry in data if 'host' in entry]
                with open(filtered_path, "w") as out:
                    out.write("\n".join(subdomains))
        except Exception as e:
            print(f"[!] Error processing subfinder JSON: {e}")

        amass_commands = [
            f"amass enum -d {domain} -config /root/.config/amass/config.yaml -min-for-recursive 2 -passive -rf /opt/resolvers/resolvers.txt -o amass_config_passive.txt",
            f"amass enum -d {domain} -config /root/.config/amass/config.yaml -min-for-recursive 2 -active -rf /opt/resolvers/resolvers.txt -o amass_config_active.txt",
            f"amass enum -d {domain} -active -rf /opt/resolvers/resolvers.txt -min-for-recursive 2 -o amass_noconfig_active.txt",
            f"amass enum -d {domain} -passive -rf /opt/resolvers/resolvers.txt -min-for-recursive 2 -o amass_noconfig_passive.txt",
            f"amass enum -d {domain} -brute -rf /opt/resolvers/resolvers.txt -min-for-recursive 2 -o amass_brute.txt"
        ]
        for cmd in amass_commands:
            run_command(cmd)

        amass_domains = set()
        target_domain = domain.lower().rstrip('.')  # Normalize target domain

        # Process Amass files
        for f in os.listdir(unfiltered_dir):
            if f.startswith("amass") and (f.endswith(".txt") or f.endswith(".json")):
                with open(unfiltered_dir / f) as infile:
                    for line in infile:
                        line = line.strip()
                        line = re.sub(r'\x1b\[[0-9;]*m', '', line)  # Remove ANSI colors
                        
                        # Skip non-domain lines (ASN, netblocks, IPs)
                        if any(x in line for x in ["(ASN)", "(Netblock)", "(IPAddress)"]):
                            continue
                        
                        # Extract potential domains (handles both FQDN-marked and raw formats)
                        if "(FQDN)" in line:
                            # Format: "static.wuzzuf.net (FQDN) --> ..."
                            fqdn = line.split("(FQDN)")[0].strip()
                        else:
                            # Format: "static.wuzzuf.net" or "static.wuzzuf.net --> ..."
                            fqdn = line.split()[0].split('-->')[0].strip().rstrip('.')
                        
                        # Validate domain match
                        if fqdn.lower().endswith(f".{target_domain}") or fqdn.lower() == target_domain:
                            amass_domains.add(fqdn.lower())

        # Save filtered Amass results
        with open(amass_filtered_file, "w") as outfile:
            outfile.write("\n".join(sorted(amass_domains)))
        print(f"[+] Amass results saved to: {amass_filtered_file}")

        # Process Subfinder results (unchanged)
        subfinder_domains = set()
        with open(filtered_path) as sf:
            subfinder_domains.update(line.strip().lower().rstrip('.') for line in sf if line.strip())

        # Combine and deduplicate
        all_unique = amass_domains.union(subfinder_domains)
        with open(final_filtered_file, "w") as final:
            final.write("\n".join(sorted(all_unique)))

    # ===================== SUBDOMAIN VERIFICATION =====================
    if selected(2) and (not approval_mode or confirm_step("Subdomain Verification")):
        alive_file = filtered_dir / "alive_domains.txt"
        run_command(f"cat {final_filtered_file} | httpx -silent -o {alive_file}")
        run_command(f"eyewitness --web -f {alive_file} -d {filtered_dir}/eyewitness")

    # ===================== CRAWLING DOMAINS =====================
    if selected(3) and (not approval_mode or confirm_step("Crawling Domains")):
        run_command(f"echo https://{domain} | hakrawler -subs -insecure -u -w > {endpoints_dir}/hakrawler_urls.txt")
        run_command(f"katana -u {domain} -jsl -jc -silent -o {endpoints_dir}/katana_urls.txt")

        current_results = set()
        for result_file in ["hakrawler_urls.txt", "katana_urls.txt"]:
            with open(endpoints_dir / result_file) as f:
                current_results.update(line.strip() for line in f if line.strip())
        
        handle_unique_items(endpoints_dir, current_results, "merged_results.txt")

    # ===================== PORT SCANNING =====================
    if selected(4) and (not approval_mode or confirm_step("Port Scanning")):
        run_command(f"nmap -sS -A -T5 -Pn -v --max-retries 2 -p {ports_to_scan} -o {scan_dir}/{domain}_scan-results.txt {domain}")

    # ===================== URL GATHERING =====================
    if selected(5) and (not approval_mode or confirm_step("URL Gathering & Param Discovery")):
        run_command(f"cat {final_filtered_file} | waybackurls > {history_dir}/urls_waybackurl.txt")
        run_command(f"gau --subs --threads 50 {domain} > {history_dir}/urls_gau.txt")
        run_command(f"waymore -i {domain} -oU {history_dir}/urls_waymore.txt -mode U")

        current_urls = set()
        for url_file in ["urls_waybackurl.txt", "urls_gau.txt", "urls_waymore.txt"]:
            with open(history_dir / url_file) as f:
                current_urls.update(line.strip() for line in f if line.strip())
        
        handle_unique_items(history_dir, current_urls, "merged_results.txt")

    # ===================== DIRECTORY BRUTEFORCE =====================
    if selected(6) and (not approval_mode or confirm_step("Directory Bruteforce")):
        sorted_dir = brute_force_dir / "sorted"
        sorted_dir.mkdir(exist_ok=True)
        
        current_urls = set()
        for wordlist in directory_selected_paths:
            output_file = brute_force_dir / f"{wordlist.name.replace('.txt','')}-files_wordlist_result.txt"
            #run_command(f"ffuf -u https://{domain}/FUZZ -w {wordlist} -e .php,.html,.bak,.txt,.conf,.log,.zip,.sql -o {output_file} -of json")
            run_command(f"ffuf -u https://{domain}/FUZZ -w {wordlist} -o {output_file} -of json")
            
            try:
                with open(output_file) as f:
                    results = json.load(f).get("results", [])
                current_urls.update(result['url'] for result in results)
            except Exception as e:
                print(f"[!] Error processing {output_file}: {e}")

        handle_unique_items(brute_force_dir / "sorted", current_urls, "merged_results.txt")

    # ===================== SUBDOMAIN BRUTEFORCE =====================
    if selected(7) and (not approval_mode or confirm_step("Subdomain Bruteforce")):
        new_total = set()
        for wordlist in subdomain_selected_paths:
            outfile = wordlist.name.replace(".txt", "_brute.txt")
            output_path = brute_sub_dir / outfile
            run_command(f"shuffledns -d {domain} -w {wordlist} -r /opt/resolvers/resolvers.txt -mode bruteforce -o {output_path}")
            
            if output_path.exists():
                with open(output_path) as f:
                    new_total.update(line.strip() for line in f if line.strip())

        handle_unique_items(brute_sub_dir, new_total, "merged_results.txt")

    print("\n[+] Recon process complete.")







