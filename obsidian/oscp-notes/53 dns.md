
- **NS**: Nameserver records (authoritative servers hosting the DNS records for a domain)
- **A**: host record - IPv4 address of a hostname
- **AAAA**: IPv6 address of a hostname
- **MX**: Mail Exchange records  (email servers for the domain, can have multiple)
- **PTR**: reverse lookup zones - domainname for a IP address
- **CNAME**: Canonical Name Records - aliases for other host records
- **TXT**: Text record - contain any arbitrary data and be used for various purposes
# ***nmap***
```shell
sudo nmap -v -Pn -n -sCV -O -p53 `tip` -oN nmap_dns_MACHINE 
# --script "fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport"

# zone transfer
sudo nmap -v Pn -n -sCV -p53 --script=dns-zone-transfer <domain_name>
```
# ***dig***
```shell
dig @`tip` any `dom`
dig @`tip` axfr `dom`
```
# ***host***
```shell
host www.megacorpone.com # A record default
host -t mx `dom`
host -t txt `dom`
```
# ***dnsrecon***
```shell
# standard / brueteforce scan
dnsrecon -d `dom` -t std
dnsrecon -d `dom` -D /usr/share/wordlists/seclists/Discovery/DNS/dns-... -t brt
```
# ***dnsenum***
```shell
dnsenum megacorpone.com
```

# ***windows***
```shell
# A record
nslookup mail.megacorptwo.com

# TXT record w/ specified server
nslookup -type=TXT info.megacorpone.com
```