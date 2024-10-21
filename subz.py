import subprocess
import argparse
import os
import re
import time
from pathlib import Path
from datetime import datetime, timedelta
from colorama import Fore, Style, init

init(autoreset=True)

required_tools = [
    "assetfinder", "findomain", "vita", "curl", "jq", "subfinder", 
    "puredns", "gotator", "dsieve", "mksub", "httpx", "amass", 
    "shuffledns", "sublist3r", "massdns", "crobat", "dnsx", "github-subdomains"
]

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

def install_tool(tool):
    print(f"{Fore.CYAN}Installing {tool}...{Style.RESET_ALL}")
    if tool == "assetfinder":
        subprocess.run("go install github.com/tomnomnom/assetfinder@latest", shell=True)
    elif tool == "findomain":
        subprocess.run("curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux && chmod +x findomain-linux && mv findomain-linux /usr/local/bin/findomain", shell=True)
    elif tool == "vita":
        subprocess.run("go install github.com/cgboal/sonarsearch/cmd/vita@latest", shell=True)
    elif tool == "subfinder":
        subprocess.run("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", shell=True)
    elif tool == "amass":
        subprocess.run("go install github.com/OWASP/Amass/v3/...@latest", shell=True)
    elif tool == "shuffledns":
        subprocess.run("go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", shell=True)
    elif tool == "sublist3r":
        subprocess.run("pip install sublist3r", shell=True)
    elif tool == "httpx":
        subprocess.run("go install github.com/projectdiscovery/httpx/cmd/httpx@latest", shell=True)
    elif tool == "massdns":
        subprocess.run("git clone https://github.com/blechschmidt/massdns.git && cd massdns && make", shell=True)
    elif tool == "crobat":
        subprocess.run("go install github.com/cgboal/sonarsearch/cmd/crobat@latest", shell=True)
    elif tool == "dnsx":
        subprocess.run("go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", shell=True)
    elif tool == "github-subdomains":
        subprocess.run("go install github.com/gwen001/github-subdomains@latest", shell=True)
    else:
        print(f"{Fore.YELLOW}No automated installation available for {tool}. Please install it manually.{Style.RESET_ALL}")

def run_command(command):
    start_time = time.time()
    print(f"{Fore.MAGENTA}{Style.BRIGHT}[{datetime.now()}] Starting: {command}{Style.RESET_ALL}")
    
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    elapsed_time = time.time() - start_time
    elapsed_str = str(timedelta(seconds=elapsed_time))
    print(f"{Fore.GREEN}[{datetime.now()}] Finished: {command} | Elapsed Time: {elapsed_str}{Style.RESET_ALL}")
    
    return result.stdout

def extract_emails_and_clean_subdomains(file_path, output_dir):
    """Extract emails from the file and clean subdomains."""
    subdomains = []
    emails = []
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if re.match(email_regex, line):
                emails.append(line)
            else:
                subdomains.append(line)

    with open(f"{output_dir}/cleaned-subdomains.txt", "w") as subdomain_file:
        subdomain_file.write("\n".join(subdomains))
    
    with open(f"{output_dir}/emails.txt", "w") as email_file:
        email_file.write("\n".join(emails))

    print(f"{Fore.GREEN}Extracted {len(emails)} emails and {len(subdomains)} subdomains.{Style.RESET_ALL}")

def combine_subdomains(output_dir):
    """Combine all the subdomain result files into one final file."""
    combined_file = os.path.join(output_dir, "final_combined.txt")
    with open(combined_file, "w") as outfile:
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith(".txt") and "combined" not in file: 
                    with open(os.path.join(root, file), "r") as infile:
                        outfile.write(infile.read())
    print(f"{Fore.CYAN}Combined all subdomains into {combined_file}{Style.RESET_ALL}")
    return combined_file

def process_domain(domain):
    output_dir = f"out/{domain}"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    with open(f"{output_dir}/scan-results.txt", "w") as export_file:
        export_file.write(f"Subdomain enumeration for {domain} started at {datetime.now()}\n")
    
    steps = [
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
    
    total_steps = len(steps)
    start_time = time.time()
    
    for i, step in enumerate(steps, 1):
        step_start_time = time.time()
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[Step {i}/{total_steps}] {step['description']} started...{Style.RESET_ALL}")
        
        run_command(step['command'])
        
        elapsed_time = time.time() - start_time
        remaining_time = (elapsed_time / i) * (total_steps - i)
        
        print(f"{Fore.GREEN}Elapsed Time: {str(timedelta(seconds=elapsed_time))}{Style.RESET_ALL}")
        
        subdomains_file = f"{output_dir}/{step['description'].lower().replace(' ', '_')}.txt"
        if os.path.exists(subdomains_file):
            with open(subdomains_file) as f:
                subdomains = f.read().splitlines()
            print(f"{Fore.GREEN}Subdomains found in this step: {len(subdomains)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No subdomains found in this step.{Style.RESET_ALL}")
        
        with open(f"{output_dir}/scan-results.txt", "a") as export_file:
            export_file.write(f"Step {i}/{total_steps} - {step['description']} completed\n")
            export_file.write(f"Elapsed Time: {str(timedelta(seconds=elapsed_time))}\n")
            export_file.write(f"Subdomains found in this step: {len(subdomains) if os.path.exists(subdomains_file) else 0}\n")
        
        step_elapsed_time = time.time() - step_start_time
        print(f"{Fore.CYAN}Step {i}/{total_steps} completed in {str(timedelta(seconds=step_elapsed_time))}\n{Style.RESET_ALL}")

    final_combined_file = combine_subdomains(output_dir)

    print(f"{Fore.CYAN}Separating emails from subdomains...{Style.RESET_ALL}")
    extract_emails_and_clean_subdomains(final_combined_file, output_dir)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}Running HTTPX on combined subdomains...{Style.RESET_ALL}")
    run_command(f"httpx -l {final_combined_file} -silent -o {output_dir}/httpx-live-subdomains.txt")

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
