# conntrack_exporter

## Uses

* **Operations**: monitor when a critical link between your microservices is broken or behaving strangely.
* **Security**: monitor which remote hosts your server is talking to.


## Features

conntrack_exporter exposes Prometheus metrics showing the state and remote endpoint for each connections on the server. For example:

```
# HELP conntrack_opening_connections_total How many connections to the remote host are currently opening?
# TYPE conntrack_opening_connections_total gauge
conntrack_opening_connections_total{host="sub.domain1.com"} 2
conntrack_opening_connections_total{host="sub.domain2.com"} 0

# HELP conntrack_open_connections_total How many open connections are there to the remote host?
# TYPE conntrack_open_connections_total gauge
conntrack_open_connections_total{host="sub.domain1.com"} 49
conntrack_open_connections_total{host="sub.domain2.com"} 19

# HELP conntrack_closing_connections_total How many connections to the remote host are currently closing?
# TYPE conntrack_closing_connections_total gauge
conntrack_closing_connections_total{host="sub.domain1.com"} 0
conntrack_closing_connections_total{host="sub.domain2.com"} 1

# HELP conntrack_closed_connections_total How many connections to the remote host have recently closed?
# TYPE conntrack_closed_connections_total gauge
conntrack_closed_connections_total{host="sub.domain1.com"} 3
conntrack_closed_connections_total{host="sub.domain2.com"} 0
```


## Quick Start

```
docker run -d --cap-add=NET_ADMIN --net=host --name=conntrack_exporter -p 9100:9100 hiveco/conntrack_exporter:0.1
```

Then open http://localhost:9100/metrics in your browser.


## Connection States

There are four possible states a TCP connection can be in: opening, open, closing, and closed. These map to traditional [TCP states](https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.1.0/com.ibm.zos.v2r1.halu101/constatus.htm) as follows:

|TCP State|Reported As|
|-----|-----|
|SYN_SENT|Opening|
|SYN_RECV|Opening|
|ESTABLISHED|Open|
|FIN_WAIT|Closing|
|CLOSE_WAIT|Closing|
|LAST_ACK|Closing|
|TIME_WAIT|Closing|
|CLOSE|Closed|

The TCP states are generalized as above because they tend to be a useful abstraction for typical users, and because they help minimize overhead.


## FAQs

### Doesn't Prometheus already monitor the system's connections natively?

Not exactly. Prometheus's [node_exporter](https://github.com/prometheus/node_exporter/) has the disabled-by-default `tcpstat` module, which exposes the number of connections in each TCP state. It does not expose which remote hosts are being connected to and which states those connections are in.

`tcp_stat` parses `/proc/net/tcp` to obtain its metrics. On busy servers, parsing a large number of connection entries would have made that module perform poorly. In addition, there would be significant overhead for Prometheus to scrape and store the large amount of constantly-changing label:value pairs of metrics that such a busy server would expose. So it was decided (link?) to expose only totals for each TCP state, which is quite a reasonable choice for the typical user.

conntrack_exporter exists to put that choice in the hands of the user. It is written in C++ (`node_exporter` is written in Golang) and instead of parsing `/proc/net/tcp`, it uses [libnetfilter_conntrack](https://www.netfilter.org/projects/libnetfilter_conntrack/) for direct access to the Linux kernel's connection table. This should make it reasonably fast even on busy servers, and allows more visibility into what's behind the summarized totals exposed by `tcpstat`.

### I know some open connections were closed, why is `conntrack_closed_connections_total` not reporting them?

conntrack_exporter just exposes the system's connection table in a format Prometheus can scrape, and it's likely the closed connections are being dropped from the system table very quickly. It could be that this guage goes up for some short period and then goes back down again before your Prometheus server can scrape it.

Either increase the scrape frequency so Prometheus is more likely to notice the change, or increase how long the system "remembers" closed connections, which is controlled by `nf_conntrack_tcp_timeout_close` (this value is in seconds).

Check the current setting:
```
sysctl net.netfilter.nf_conntrack_tcp_timeout_close
```

Update it:
```
echo "net.netfilter.nf_conntrack_tcp_timeout_close = 60" >> /etc/sysctl.conf
sysctl -p
```

**WARNING:** Raising this setting too high is not recommended, especially on high-traffic servers, because it'll overflow your system's connection table due to all the extra closed connections it has to keep track of.

Similar issues with other connection states (besides `closed`) might be resolved by updating the other `net.netfilter.nf_conntrack_tcp_timeout_*` settings. Run `sysctl -a | grep conntrack | grep timeout` to see all available settings.
