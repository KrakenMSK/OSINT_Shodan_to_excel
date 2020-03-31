# OSINT_Shodan_to_exel
OSINT tool to collect info about organization's networks and present it in .xlsx format

To collect info about your company make file with researching networks and put networks to them.


example:

x.x.x.x

x.x.x.x/x

Then start program with two keys: shodan_key and file to path with networks:


###################################################################

git clone https://github.com/KrakenMSK/OSINT_Shodan_to_exel

cd OSINT_Shodan_to_exel

python3 -m pip install -r requirements.txt

python3 <shodan_key> <path_to_file_with_networks>

###################################################################

logs: all_collected_data.txt

exel table: info_about_organization.xlsx
