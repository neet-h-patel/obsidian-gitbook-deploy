## list listening ports
```shell
ss -tulpn
```
## kill tcp ports
```shell 
sudo lsof -i tcp:<PORT>

kill <PID>
# https://serverfault.com/questions/290780/close-tcp-port-with-no-process
```
## box64
```shell
git clone https://github.com/ptitSeb/box64
cd box64
mkdir build; cd build; cmake .. -D ARM_DYNAREC=ON -D CMAKE_BUILD_TYPE=RelWithDebInfo

make -j4
sudo make install
sudo systemctl restart systemd-binfmt
```
## xenspwn (old target kernel compilation)
```shell
# https://github.com/X0RW3LL/XenSpawn
```

## static binaries
```
https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap
https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/strings
```
