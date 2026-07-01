# Network Scanner

A Python-based network security scanner that generates human-readable HTML reports from nmap scan data. Built as part of the Sara T. Slocum Digital Scholarship Internship at Haverford College Libraries.

## What it does

- Scans a target IP or subnet for open ports and running services
- Rates each finding by severity (High / Medium / Info)
- Generates a clean HTML report with plain-English explanations and remediation guidance

## Requirements

- Python 3.x
- nmap installed and in PATH
- python-nmap library

## Installation

```bash
pip install python-nmap
```

## Usage

Edit the target IP at the bottom of `scanner.py`:

```python
scan_target('YOUR_TARGET_IP')
```

Then run:

```bash
python scanner.py
```

An HTML report will be generated in the same folder.

## Example Output

- 6 High severity findings
- 3 Medium severity findings  
- 3 Info findings

## Context

This tool was built as a technical portfolio piece during a 10-week cybersecurity awareness internship. The companion deliverable is a public-facing knowledge base article on digital safety best practices for the Haverford campus community.

## Disclaimer

Only run this tool against networks and devices you have explicit permission to scan.