#!/bin/bash

mkdir  -p $1/{recon,nuclei,jaeles,subtko,waybackurls,js,eyewitness,ports,BLC,clickjack}
Divide="***************************************************************************"

echo "Gathering Subdomain"
echo $Divide
sleep 15

subfinder -silent -d $1 > $1/recon/Subdomain.txt 
gau -subs $1 | cut -d / -f 3 | cut -d ":" -f 1| sort -u >> $1/recon/Subdomain.txt 
assetfinder -subs-only $1 >> $1/recon/Subdomain.txt 
findomain -t $1 -q -u $1/recon/findomain.txt
for domain in $(cat findomain.txt );do findomain -t $domain -q ;done >> $1/recon/Subdomain.txt 

sleep 15

echo "Sorting Subdomain"
echo $Divide
sleep 15

cat $1/recon/Subdomain.txt| sort -u | uniq > $1/recon/Final_subdomain.txt


echo "Testing for Alive Subdomains"
echo $Divide
sleep 15
cat $1/recon/Final_subdomain.txt| httpx -silent > $1/recon/ALive.txt


echo "Sending all URLs to Nuclei|Sit Back and Relax"
echo $Divide
sleep 15


echo "Testing for CVEs"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/cves/ -silent -c 20 -o $1/nuclei/cve.txt

echo "Testing for Subdomain Takeover"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/takeovers/ -silent -c 20 -o $1/nuclei/subtko.txt


echo "Testing for security misconfiguration"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/misconfiguration/ -silent -c 20 -o $1/nuclei/sec_misconfig.txt

echo "Testing for Files"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/exposures/files/  -silent -c 20 -o $1/nuclei/Files.txt

echo "Testing for Vulnerabilities "
echo "------------------------------------------------------"

nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/vulnerabilities/ -silent -c 20 -o $1/nuclei/Vuln.txt

echo "testing for Default Logins"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/default-logins/ -silent -c 20 -o $1/nuclei/Default.txt

echo "Testing Miscellaneous"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/miscellaneous/ -silent -c 20 -o $1/nuclei/misc.txt

echo "backup Files"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/exposures/backups/ -silent -c 20 -o $1/nuclei/backup.txt

echo "DNS"
echo "------------------------------------------------------"
nuclei -l $1/recon/Final_subdomain.txt -t ~/nuclei-templates/dns/ -silent -c 20 -o $1/nuclei/DNS.txt


echo "Grabbing Screenshots "
echo $Divide
cat $1/recon/ALive.txt | aquatone -o $1/screenshot/aquatone

echo "Scanning for Open Ports"
echo $Divide
naabu -v -silent -iL $1/recon/Subdomain.txt -o $1/ports/naabu_port.txt   
nmap -sC -sV -iL $1/recon/ALive.txt -t 3 -o $1/ports/nmap

echo "Testing for Subdomain Takeover"
echo $Divide
SubOver -l $1/recon/Subdomain.txt -v > $1/subtko/output.txt
sleep 30

echo "Analysing Js Files"
echo $Divide
cat $1/waybackurls/wayback.txt | grep "\.js" | uniq | sort > $1/waybackurls/js.txt
cat $1/waybackurls/js.txt | hakcheckurl | grep -v 404 | grep -v 500 | grep -v 410 > $1/js/js_alive.txt


echo "Checking For Broken Links"
echo $Divide
for domain in $(cat $1/recon/ALive.txt );do blc $domain;done >> $1/BLC/broken_link.txt

echo "Checking For Clickjacking"
echo $Divide
sleep 15
python3 ~/tools/clickjack/clickjack.py $1/recon/ALive.txt | grep -v "NOT" | awk '{print $2}' >> $1/clickjack/vulnerable.txt


