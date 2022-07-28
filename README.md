# tcp rst detect

This project is designed to detect RST packet after ClientHello of TLS connection and add remote address into ipset,
so the future connections can be redirected though the ipset

# usage

this program will sniff packet of an interface, so **it requires root**

```bash
CGO_ENABLED=1 go build -trimpath .
# sniff interface is `eth0`, target ipset is `ipset`
sudo ./tcp-rst-detect -i eth0 -s ipset
```

# other

The `ip-domain-rst` relation is store in `data.db` by default. You can query which domains and ips have rst connections
