#!/bin/bash

echo "Gathering Subdomain"
echo "*************************************************************************"
subfinder -d $1 > Subdomain.txt 
gau -subs $1 | cut -d / -f 3 | cut -d ":" -f 1| sort -u >> Subdomain.txt 
assetfinder -subs-only $1 >> Subdomain.txt 

echo "Sorting Subdomain"
echo "*************************************************************************"
cat Subdomain.txt| sort -u | uniq > Final_subdomain.txt;rm Subdomain.txt

echo "Testing for Alive Subdomains"
echo "*************************************************************************"
cat Final_subdomain.txt| httpx > ALive.txt

echo "Scanning for Open Ports"
echo "*************************************************************************"



echo "Grabbing Screenshots "
echo "*************************************************************************"

python3 ~/tools/EyeWitness/Python/EyeWitness.py -f ALive.txt -d Eyewitness --web




