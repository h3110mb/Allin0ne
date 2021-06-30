#!/bin/bash


echo "Testing for CVEs"
echo "----------------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/cves/ -silent -c 20 

echo "Testing for Subdomain Takeover"
echo "-----------------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/takeovers/ -silent -c 20 


echo "Testing for security misconfiguration"
echo "------------------------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/misconfiguration/ -silent -c 20 
echo "Testing for Files"
echo "-------------------------------"

nuclei -l $1 -t ~/nuclei-templates/exposures/files/  -silent -c 20
echo "Testing for Vulnerabilities "
echo "--------------------------------------"

nuclei -l $1 -t ~/nuclei-templates/vulnerabilities/ -silent -c 20 

echo "testing for Default Logins"
echo "----------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/default-logins/ -silent -c 20 

echo "Testing Miscellaneous"
echo "-----------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/miscellaneous/ -silent -c 20 

echo "backup Files"
echo "-----------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/exposures/backups/ -silent -c 20 

echo "DNS"
echo "-----------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/dns/ -silent -c 20 

echo "Fuzzing "
echo "-----------------------------------------"
nuclei -l $1 -t ~/nuclei-templates/fuzzing/ -silent -c 20