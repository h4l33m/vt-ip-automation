\# VirusTotal IP Automation Script



This Python script checks IP reputation using the VirusTotal API and saves results to a CSV file.



\## Features

\- Bulk IP lookup from file

\- Extracts reputation, ASN, country

\- Outputs results to CSV



\## Requirements

\- Python 3.x

\- VirusTotal API key



\## Setup



1\. Clone the repo:



git clone https://github.com/h4l33m/vt-ip-automation.git

cd vt-ip-automation



2\. Install dependencies:



pip install -r requirements.txt



3\. Create `.env` file:



VT\_API\_KEY=your\_api\_key\_here



4\. Add IPs to `input.txt`



\## Run

python vt\_ip\_check.py



\## Output

\- `vt\_results.csv`



\## Notes

\- Free VirusTotal API is rate-limited

\- Increase delay if you get 429 errors





