Red Hat CVE Report Generator

Author: Brandon Williams
Description: This utility makes calls to the Red Hat CVE database to retrieve the CVE details.
Usage: This script takes a list of CVEs as input and produces a report containing details, statements, and links to any related errata.
       The input file should be plain text with one CVE per line. e.g.:

       CVE-2015-0409
       CVE-2015-0411
       CVE-2015-0432
       ...

Syntax: redhat_cve_report.sh <CVE_List> to use as input

CVE_List.txt contains a sample CVE List
CVE_Report.txt contains a sample report

Version 0.1 - February 19, 2015
- Initial version