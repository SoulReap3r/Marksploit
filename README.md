# TomSploit — AD Enumeration
Automates NetExec across all protocols and auth methods, summarises results, and suggests follow-up commands based on what succeeded.

# Set up

git clone https://github.com/twhitehead290/TomSploit.git 

chmod +x /path/to/TomSploit.py

sudo cp /path/to/TomSploit.py /usr/local/bin/TomSploit

# Usage

netexec-automator -t TARGET -u USER -p PASSWORD

netexec-automator -t live_hosts.txt -u USER -p PASSWORD
