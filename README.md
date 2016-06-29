## snoop connbal

This is a tool for assessing how well an app/container is making use of multiple
A or SRV records returned from DNS.

It takes in a "snoop" packet capture stream and processes it, tracking DNS
request/response cycles, and then watching TCP connection attempts to hosts
that were returned in DNS.

At the end of the capture stream, it prints out a summary like the following:

```
172.016.101.190	172.016.100.149:80	5	16	web.svc.acct.us-west-1.cns.joyent.com.
172.016.101.190	172.016.100.219:80	3	16	web.svc.acct.us-west-1.cns.joyent.com.
172.016.101.190	172.016.100.245:80	2	16	web.svc.acct.us-west-1.cns.joyent.com.
172.016.101.190	172.016.101.021:80	6	16	web.svc.acct.us-west-1.cns.joyent.com.
172.016.101.190	165.225.123.123:5222	0	1	_xmpp-client._tcp.example.com
172.016.101.190	165.225.123.124:5222	1	1	_xmpp-client._tcp.example.com.
172.016.101.190	165.225.123.125:5222	0	1	_xmpp-client._tcp.example.com.
```

The columns here are:

```
source ip	destination ip : port	#conns	#dns	dns name
```

 * `source ip` -- the client that is making connections and resolving names
 * `destination ip : port` -- the "backend" that it's connecting out to
 * `#conns` -- the total number of connections made to this backend
 * `#dns` -- the number of times this backend appeared in DNS results
 * `dns name` -- the original name that the client looked up to get this backend

In the example output above, we can observe that our app/container is making two
kinds of outgoing connections to multi-backend services -- one CNS service name
(`web.svc.acct.us-west-1.cns.joyent.com.`), and one XMPP service, which it is
looking up using SRV records (`_xmpp-client._tcp.example.com.`).

We can see that the CNS service name was returning 4 different backend IPs as
A records (which it returned consistently the entire time -- hence they all have
a `#dns` count of 16), and while we connected to all 4, it wasn't quite an even
distribution between them. We can also see that our app is making 1 DNS lookup
for every single backend connection -- which is a bad sign worthy of some
follow-up (the app should respect the TTL and cache instead).

The XMPP SRV lookup returned 3 servers, of which we only connected to one. This
is probably fine, but can also be useful knowledge.

### Building and using

```
$ make
cc -o connbal connbal.c hash.c packet.c
```

You can also download binaries for OSX and Illumos/SmartOS from the
["Releases" section on GitHub](https://github.com/arekinath/snoop-conn-balance/releases).

Basic example of using it:

```
$ time snoop -c 1000 -s 0 -o /dev/stdout '(tcp and tcp[13] == 0x02) or (udp and port 53)' | ./connbal | sort -n
```

We filter the `snoop` to cover only TCP SYN packets and UDP packets involving
port 53 -- this way the kernel is not sending huge amounts of data to userland
that `connbal` is simply going to discard anyway.

The `sort -n` and `time` commands are useful to make the output more readable
(and you can tell if TTLs are being respected by comparing the number of
lookups to the time sampled).

We can also use the new `-a` option, which can assess ongoing TCP streams as well as new SYNs:

```
$ time snoop -s 0 -o /dev/stdout '(tcp and less 128) or (udp and port 53)' | ./connbal -a
Using device net0 (promiscuous mode)
22734 ^C
172.023.024.042 172.023.024.012:1390    1       8       _ldap._tcp.ufds.coal.cns.joyent.us.
172.023.024.042 172.023.024.012:1391    1       8       _ldap._tcp.ufds.coal.cns.joyent.us.
172.023.024.042 172.023.024.012:1392    2       8       _ldap._tcp.ufds.coal.cns.joyent.us.
172.023.024.042 172.023.024.012:1393    1       8       _ldap._tcp.ufds.coal.cns.joyent.us.
172.023.024.042 172.023.024.005:53      0       8       _dns._udp.binder.coal.cns.joyent.us.

real    0m20.929s
user    0m0.211s
sys     0m0.573s
```

In this case, we only want to filter to "small" TCP packets (to avoid moving
lots of bulk data to userland) as well as DNS. Using the `-a` option can be
expensive in memory and CPU on busy networks (expect 10-20% of a core in CPU
time and 1-2MB of memory per minute on a 12 CN SDC cluster observing CNS
during an update run), but it's the only way to assess connection balance of
ongoing connections as well as newly made ones.

The `-F` option can also be used to filter the names that will be tracked:

```
$ time snoop -s 0 -o /dev/stdout '(tcp and less 128) or (udp and port 53)' | ./connbal -a -F binder
Using device net0 (promiscuous mode)
22730 ^C
172.023.024.042 172.023.024.005:53      0       8       _dns._udp.binder.coal.cns.joyent.us.

real    0m19.429s
user    0m0.198s
sys     0m0.610s
```

This is useful if there are a lot of other irrelevant DNS lookups going on and
you want to avoid `connbal` wasting its time and memory tracking them.
