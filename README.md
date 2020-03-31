# OSINT_Shodan_to_exel
OSINT tool to collect info about organisation's networks and present it in .xlsx format

To collect info about your company make file with researching networks and put networks to them.
example:
10.11.12.13
10.11.13.22
93.22.12.33/x

Then start program with two keys: shodan_key and file to path with networks:

git clone https://github.com/KrakenMSK/OSINT_Shodan_to_exel

cd OSINT_Shodan_to_exel

python3 install -r requirements.txt

python3 <shodan_key> <path_to_file_with_networks>
