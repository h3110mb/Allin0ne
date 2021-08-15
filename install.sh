#/bin/sh

sudo apt-get install git;
sudo apt-get install python3;
sudo apt-get install python3-pip;
sudo apt-get install ruby;
sudo apt-get install screen;
sudo apt-get install golang;
sudo apt-get install nodejs;

mkdir ~/tools;

go get -u github.com/tomnomnom/gf;
go get github.com/tomnomnom/hacks/waybackurls;
go get -u github.com/tomnomnom/assetfinder;go get -u github.com/tomnomnom/qsreplace;
go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei;
git clone https://github.com/projectdiscovery/nuclei-templates;
GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder;
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx;
GO111MODULE=on go get -u -v github.com/lc/gau;
go get github.com/Ice3man543/SubOver;
GO111MODULE=on go get -u github.com/jaeles-project/gospider;
GO111MODULE=on go get -u -v github.com/lc/subjs;
GO111MODULE=on go get -v github.com/hahwul/dalfox/v2;
cd ~/tools;
git clone https://github.com/devanshbatham/ParamSpider;
git clone https://github.com/1ndianl33t/Gf-Pattern; mkdir .gf; mv ~/Gf-Patterns/*.json ~/.gf;
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux; mv findomain-linux findomain; chmod +x findomain;
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip;unzip aquatone_linux_amd64_1.7.0.zip, cp aquatone /usr/local/bin ;
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder;cd secretfinder;pip install -r requirements.txt;cd ~/tools;
git clone https://github.com/GerbenJavado/LinkFinder.git;cd LinkFinder;python setup.py install;cd ~/tools;
git clone https://github.com/devanshbatham/ParamSpider;cd ParamSpider;pip3 install -r requirements.txt;cd ~/tools;
npm install broken-link-checker -g;
git clone https://github.com/saleem8054/clickjack.git;
cd ~/go/bin; cp * /usr/local/bin;



 
