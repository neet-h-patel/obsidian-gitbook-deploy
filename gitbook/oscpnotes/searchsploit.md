```shell
# Search
searchsploit SERVERS VERSIONS PLUGINS
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```

```shell
# Examine
searchsploit -x NUMBER
```

```shell
# Copy
searchsploit -m NUMBER
```