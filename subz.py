import subprocess
import argparse
import os
import re
import time
from pathlib import Path
from datetime import datetime, timedelta
from colorama import Fore, Style, init
import glob

init(autoreset=True)

required_tools = {
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "findomain": "curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux && chmod +x findomain-linux && mv findomain-linux /usr/local/bin/findomain",
    "vita": "go install github.com/cgboal/sonarsearch/cmd/vita@latest",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "go install github.com/OWASP/Amass/v3/...@latest",
    "shuffledns": "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
    "sublist3r": "pip install sublist3r",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "massdns": "git clone https://github.com/blechschmidt/massdns.git && cd massdns && make",
    "puredns": "go install github.com/d3mondev/puredns/v2/cmd/puredns@latest",
    "gotator": "go install github.com/Josue87/gotator@latest",
    "crobat": "go install github.com/cgboal/sonarsearch/cmd/crobat@latest",
    "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "github-subdomains": "go install github.com/gwen001/github-subdomains@latest",
    "dnsbruter": "go install github.com/root4loot/dnsbruter@latest",
    "subdominator": "go install github.com/projectdiscovery/subdominator@latest",
    "subprober": "go install github.com/ProjectAnte/SubProber@latest"
}

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
    install_command = required_tools.get(tool, "")
    if install_command:
        subprocess.run(install_command, shell=True)
    else:
        print(f"{Fore.YELLOW}No automated installation available for {tool}. Please install it manually.{Style.RESET_ALL}")

def run_command(command, description, output_file):
    start_time = time.time()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"{Fore.CYAN}{Style.BRIGHT}Starting: {command}{Style.RESET_ALL}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    elapsed_time = time.time() - start_time
    elapsed_str = str(timedelta(seconds=int(elapsed_time)))
    
    subdomains_found = 0
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            subdomains = f.readlines()
            subdomains_found = len(subdomains)
    
    if subdomains_found > 0:
        print(f"{Fore.GREEN}[+] [{current_time}] Finished: {Fore.CYAN}{Style.BRIGHT}{command}{Style.RESET_ALL} | "
              f"{Fore.BLUE}Elapsed Time: {elapsed_str}{Style.RESET_ALL} | "
              f"{Fore.YELLOW}{Style.BRIGHT}total sub-domains found [{subdomains_found}]{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] [{current_time}] Finished: {Fore.CYAN}{Style.BRIGHT}{command}{Style.RESET_ALL} | "
              f"{Fore.BLUE}Elapsed Time: {elapsed_str}{Style.RESET_ALL} | nothing found")

def combine_and_run_httpx(domain, output_dir, final_file):
    combined_file = os.path.join(output_dir, "combined-subdomains.txt")
    
    with open(combined_file, "w") as outfile:
        for file in glob.glob(f"{output_dir}/*.txt"):
            if "scan-results.txt" not in file:
                with open(file, "r") as infile:
                    outfile.write(infile.read())

    print(f"{Fore.CYAN}Combined all subdomains into {combined_file}{Style.RESET_ALL}")
    
    final_httpx_output = os.path.join(output_dir, final_file)
    print(f"{Fore.CYAN}Running HTTPX on the combined subdomains...{Style.RESET_ALL}")
    
    run_command(f"httpx -l {combined_file} -silent -o {final_httpx_output}", "HTTPX Scan", final_httpx_output)
    
    print(f"{Fore.GREEN}Final list of live subdomains saved to {final_httpx_output}{Style.RESET_ALL}")

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

def process_domain(domain):
    output_dir = f"out/{domain}"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    with open(f"{output_dir}/scan-results.txt", "w") as export_file:
        export_file.write(f"Subdomain enumeration for {domain} started at {datetime.now()}\n")
    
    steps = [
        {"command": f"dnsbruter -d {domain} -w subs-dnsbruter-small.txt -c 200 -wt 100 -o {output_dir}/output-dnsbruter.txt", "description": "Passive FUZZ domains with wordlist", "output_file": f"{output_dir}/output-dnsbruter.txt"},
        {"command": f"subdominator -d {domain} -o {output_dir}/output-subdominator.txt", "description": "Active brute crawling domains", "output_file": f"{output_dir}/output-subdominator.txt"},
        {"command": f"assetfinder --subs-only {domain} | tee {output_dir}/assetfinder.txt", "description": "Assetfinder", "output_file": f"{output_dir}/assetfinder.txt"},
        {"command": f"findomain --target {domain} --unique-output {output_dir}/findomain.txt", "description": "Findomain", "output_file": f"{output_dir}/findomain.txt"},
        {"command": f"vita -d {domain} > {output_dir}/vita.txt", "description": "Vita", "output_file": f"{output_dir}/vita.txt"},
        {"command": f"subfinder -d {domain} -o {output_dir}/subfinder.txt", "description": "Subfinder", "output_file": f"{output_dir}/subfinder.txt"},
        {"command": f"amass enum --passive -d {domain} -o {output_dir}/amass.txt", "description": "Amass", "output_file": f"{output_dir}/amass_passive.txt"},
        {"command": f"sublist3r -d {domain} -o {output_dir}/sublist3r.txt", "description": "Sublist3r", "output_file": f"{output_dir}/sublist3r.txt"},
        {"command": f"shuffledns -d {domain} -w {output_dir}/shuffledns-output.txt -r in/resolvers.txt -o {output_dir}/shuffledns.txt", "description": "Shuffledns", "output_file": f"{output_dir}/shuffledns.txt"},
        {"command": f"puredns resolve {output_dir}/shuffledns-output.txt --resolvers in/resolvers.txt -w {output_dir}/puredns-resolved.txt", "description": "PureDNS Resolve", "output_file": f"{output_dir}/puredns-resolved.txt"},
        {"command": f"puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt {domain} --resolvers in/resolvers.txt -w {output_dir}/puredns-bruteforce.txt", "description": "PureDNS Bruteforce", "output_file": f"{output_dir}/puredns-bruteforce.txt"},
        {"command": f"massdns -r in/resolvers.txt -o S -w {output_dir}/massdns.txt {output_dir}/massdns-output.txt", "description": "MassDNS", "output_file": f"{output_dir}/massdns.txt"},
        {"command": f"crobat -d {domain} | tee {output_dir}/crobat.txt", "description": "Crobat", "output_file": f"{output_dir}/crobat.txt"},
        {"command": f"dnsx -d {domain} -r in/resolvers.txt -o {output_dir}/dnsx.txt", "description": "DNSx", "output_file": f"{output_dir}/dnsx.txt"},
        {"command": f"github-subdomains -d {domain} -o {output_dir}/github-subdomains.txt", "description": "GitHub Subdomains", "output_file": f"{output_dir}/github-subdomains.txt"}
    ]
    
    for step in steps:
        run_command(step['command'], step['description'], step['output_file'])

    combine_and_run_httpx(domain, output_dir, f"final-list.txt")

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
