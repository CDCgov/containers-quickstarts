#!/usr/bin/python

# Created by Zach Dunbrack
# Last modified: 7/16/19

import datetime
import os
import subprocess
import sys
import re

# Dictionary for keeping track of processed vulnerabilities
vuln_data = {
    "Low": {"count": 0, "grace": -1, "expired_count": 0},
    "Moderate": {"count": 0, "grace": -1, "expired_count": 0},
    "Important": {"count": 0, "grace": -1, "expired_count": 0},
    "Critical": {"count": 0, "grace": -1, "expired_count": 0}
}

# Usage guide
if len(sys.argv) != 6:
    print("Usage: report-parser.py html_report critical_grace important_grace moderate_grace low_grace")
    print("Grace periods for each level of vulnerability indicate the number of days for which a vulnerability can be known before the script exits with a nonzero exit code.")
    print("In order to never fail upon finding a vulnerability of a certain level, enter -1 as the grace period.")
    sys.exit(0)

# Fail if file does not exist.
if not os.path.exists(sys.argv[1]):
    print("File " + sys.argv[1] + " not found.")
    sys.exit(1)

levels = ["Critical", "Important", "Moderate", "Low"]
any_expired = False

# Importing command-line arguments
for i in range(len(levels)):
    vuln_data[levels[i]]["grace"] = int(sys.argv[i+2])

# Parsing and processing unpatched vulnerabilities
try:
    unpatched_vulns = subprocess.check_output(["grep", "-A", "3", "true", sys.argv[1]])
except subprocess.CalledProcessError:
    print("No vulnerabilities found! Exiting...")
    sys.exit(0)

vuln_list = unpatched_vulns.split("--")
for vuln in vuln_list:
    level_name = re.search("\([^)]+\)", vuln).group()[1:-1]
    if level_name == "None":
        continue
    if vuln_data[level_name]["grace"] >= 0:
        # Find release date from Red Hat Security Advisory page, record if older than specified grace period
        rhsa_link = re.search("https://access.redhat.com/errata/[^\"]+\"", vuln).group()[:-1]
        redhat_html = subprocess.check_output(["curl", "-s", rhsa_link])
        redhat_errata_date_string = re.search("[^\"]\d{4}-\d{2}-\d{2}", redhat_html).group()[-10:]
        redhat_errata_date_datetime = datetime.datetime.strptime(redhat_errata_date_string, "%Y-%m-%d")
        current_datetime = datetime.datetime.now()
        vuln_exposure_days = (current_datetime - redhat_errata_date_datetime).days
        if vuln_exposure_days > vuln_data[level_name]["grace"]:
            vuln_data[level_name]["expired_count"] += 1
            any_expired = True
    vuln_data[level_name]["count"] += 1

# Print results
print("Scan processed. Vulnerability count:")
for level in levels:
    print(str(level) + ": " + str(vuln_data[level]["count"]) + (" (" + str(vuln_data[level]["expired_count"]) + " older than " + str(vuln_data[level]["grace"]) + " days)" if vuln_data[level]["grace"] >= 0 else ""))

# Exit with nonzero code (failing pipeline build) if any vulnerabilities are older than the given grace period for that level
if(any_expired):
    sys.exit(1)
