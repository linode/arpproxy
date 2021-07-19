# arpproxy

this tool is capable of spoofing / injecting a custom mac for a list of IPs read (and updated) from a flat file

by doing so we can:
- leverage fast hardware asics to forward traffic while still breaking up layer2 domains
- breaking layer 2 domain in a transparent way to the client
- migrate layer 2 traffic out of a vlan into a routed environment
- by using the mac of the local interface (and using the spoofed mac in the payload) we do not break any cam/switch tables along the way


### usage:
tools comes with a systemd service unit and a /etc/default/arpproxy file
update this file to your needs

for a up2date list of options run
```
arpproxy --help
```


the list of IPs is read out of `/etc/arpproxy.list` by default but can be specified to any path
