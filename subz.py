import subprocess
import argparse
import os
import re
import time
from pathlib import Path
from datetime import datetime, timedelta
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# List of required tools
required_tools = [
    "assetfinder", "findomain", "vita", "curl", "jq", "subfinder", 
    "puredns", "gotator", "dsieve", "mksub", "httpx", "amass", 
    "shuffledns", "sublist3r", "massdns", "crobat", "dnsx", "github-subdomains",
    "dnsbruter", "subdominator", "subprober"
]

# Regular expression for detecting emails
email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

def check_tools():
    print(f"{Fore.CYAN}{Style.BRIGHT}Checking for required tools...\n{Style.RESET_ALL}")
    missing_tools = []
    for tool in required_tools:
        result = subprocess.run(f"which {tool}", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{Fore.RED}{tool}: Not installed{Style.RESET_ALL}")
            missing_tools.append(tool)
        else:
            print(f"{Fore.GREEN}{tool}: Installed{Style.RESET_ALL}")
    
    if missing_tools:
        print(f"\n{Fore.YELLOW}The following tools are missing: {', '.join(missing_tools)}{Style.RESET_ALL}")
        for tool in missing_tools:
            user_input = input(f"Do you want to install {Fore.BLUE}{tool}{Style.RESET_ALL}? [y/n]: ").strip().lower()
            if user_input == "y":
                install_tool(tool)
            else:
                print(f"{Fore.YELLOW}Skipping installation of {tool}. The script will proceed without this tool.\n{Style.RESET_ALL}")

def run_command(command):
    start_time = time.time()
    print(f"{Fore.MAGENTA}{Style.BRIGHT}[{datetime.now()}] Starting: {command}{Style.RESET_ALL}")
    
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    elapsed_time = time.time() - start_time
    elapsed_str = str(timedelta(seconds=elapsed_time))
    print(f"{Fore.GREEN}[{datetime.now()}] Finished: {command} | Elapsed Time: {elapsed_str}{Style.RESET_ALL}")
    
    return result.stdout

def process_domain(domain):

    output_dir = f"out/{domain}"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    

    with open(f"{output_dir}/scan-results.txt", "w") as export_file:
        export_file.write(f"Subdomain enumeration for {domain} started at {datetime.now()}\n")
    

    steps = [
        {"command": f"dnsbruter -d {domain} -w subs-dnsbruter-small.txt -c 200 -wt 100 -o {output_dir}/output-dnsbruter.txt -ws {output_dir}/dnsbruter_2.txt", "description": "Passive FUZZ domains with wordlist"},
        {"command": f"subdominator -d {domain} -o {output_dir}/output-subdominator.txt", "description": "Active brute crawling domains"}
        {"command": f"assetfinder --subs-only {domain} | tee {output_dir}/assetfinder.txt", "description": "Assetfinder"},
        {"command": f"findomain --target {domain} --unique-output {output_dir}/findomain.txt", "description": "Findomain"},
        {"command": f"vita -d {domain} > {output_dir}/vita.txt", "description": "Vita"},
        {"command": f"subfinder -d {domain} -o {output_dir}/subfinder.txt", "description": "Subfinder"},
        {"command": f"amass enum -d {domain} -o {output_dir}/amass.txt", "description": "Amass"},
        {"command": f"sublist3r -d {domain} -o {output_dir}/sublist3r.txt", "description": "Sublist3r"},
        {"command": f"shuffledns -d {domain} -w {output_dir}/shuffledns-output.txt -r in/resolvers.txt -o {output_dir}/shuffledns.txt", "description": "Shuffledns"},
        {"command": f"puredns resolve {output_dir}/shuffledns-output.txt --resolvers in/resolvers.txt -w {output_dir}/puredns-resolved.txt", "description": "PureDNS Resolve"},
        {"command": f"puredns bruteforce /usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt {domain} --resolvers in/resolvers.txt -w {output_dir}/puredns-bruteforce.txt", "description": "PureDNS Bruteforce"},
        {"command": f"gotator -silent -t 250 -sub {output_dir}/puredns-bruteforce.txt -md | tee {output_dir}/gotator-output.txt", "description": "Gotator"},
        {"command": f"massdns -r in/resolvers.txt -o S -w {output_dir}/massdns.txt {output_dir}/massdns-output.txt", "description": "MassDNS"},
        {"command": f"crobat -d {domain} | tee {output_dir}/crobat.txt", "description": "Crobat"},
        {"command": f"dnsx -d {domain} -r in/resolvers.txt -o {output_dir}/dnsx.txt", "description": "DNSx"},
        {"command": f"github-subdomains -d {domain} -o {output_dir}/github-subdomains.txt", "description": "GitHub Subdomains"}        
    ]
    
    for i, step in enumerate(steps, 1):
        run_command(step['command'])
    
    dnsbruter_output = f"{output_dir}/output-dnsbruter.txt"
    subdominator_output = f"{output_dir}/output-subdominator.txt"
    merged_output = f"{output_dir}/{domain}-domains.txt"
    
    if not os.path.exists(dnsbruter_output):
        if os.path.exists(subdominator_output):
            print(f"Moving {subdominator_output} to {merged_output}")
            os.rename(subdominator_output, merged_output)
        else:
            print(f"Both {dnsbruter_output} and {subdominator_output} not found. Exiting.")
            return
    else:
        if os.path.exists(subdominator_output):
            print("Merging outputs from dnsbruter and subdominator.")
            with open(merged_output, "w") as outfile:
                with open(dnsbruter_output) as infile:
                    outfile.write(infile.read())
                with open(subdominator_output) as infile:
                    outfile.write(infile.read())
        else:
            os.rename(dnsbruter_output, merged_output)
    
    unique_output = f"{output_dir}/unique-{domain}-domains.txt"
    with open(merged_output, 'r') as infile, open(unique_output, 'w') as outfile:
        seen = set()
        for line in infile:
            line = line.strip()
            if line not in seen:
                seen.add(line)
                outfile.write(line + '\n')
    
    os.remove(merged_output)
    if os.path.exists(dnsbruter_output):
        os.remove(dnsbruter_output)
    if os.path.exists(subdominator_output):
        os.remove(subdominator_output)
    
    subprober_output = f"{output_dir}/subprober-{domain}-domains.txt"
    run_command(f"subprober -f {unique_output} -sc -ar -o {subprober_output} -nc -mc 200 301 302 307 308 403 401 -c 50")
    
    final_output = f"{output_dir}/final-{domain}-domains.txt"
    run_command(f"grep -oP 'http[^\s]*' {subprober_output} > {final_output}")
    
    os.remove(unique_output)
    os.remove(subprober_output)
    os.rename(final_output, f"{output_dir}/{domain}-domains.txt")
    print(f"Enumeration and filtering process completed. Final output: {output_dir}/{domain}-domains.txt")

def main():
    parser = argparse.ArgumentParser(description="Automate Subdomain Enumeration")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain to enumerate subdomains")
    group.add_argument("-l", "--list", help="List of domains to enumerate subdomains")
    
    args = parser.parse_args()
    
    check_tools()
    
    if args.domain:
        process_domain(args.domain)
    elif args.list:
        with open(args.list) as f:
            domains = f.read().splitlines()
            for domain in domains:
                process_domain(domain)

if __name__ == "__main__":
    main()
