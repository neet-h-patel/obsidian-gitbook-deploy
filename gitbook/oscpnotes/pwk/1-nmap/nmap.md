# *tcp*
```shell
sudo nmap -v -Pn -n -sCV -O -p- --open `tip` -oN nmap_MACHINE
```
# *udp*
```shell
# top 100 / 1000
sudo nmap -v -Pn -n -sUV -T4 --top-ports 100 -F --version-intensity 0 `tip` -oN nmap_udp100_MACHINE

sudo nmap -v -Pn -n -sUV -T4 --top-ports 1000 -F --version-intensity 0 `tip` -oG nmap_udp1000_MACHINE
```
# *custom Scripts*
```shell
# 1 copy script (check name format)
sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
```

```shell
# 2 update db
sudo nmap --script-updatedb
```

```shell
# 3 run
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
```
# *resources*
```shell
# default-scripts
# https://nmap.org/nsedoc/categories/default.html
```


