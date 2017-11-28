# **conntrack_exporter**

*Prometheus exporter for network connections*

## Uses

* **Operations**: monitor when a critical link between your microservices is broken.
* **Security**: monitor which remote hosts your server is talking to.
* **Debugging**: correlate intermittently misbehaving code with strange connection patterns.


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
docker run -d --cap-add=NET_ADMIN --net=host --name=conntrack_exporter hiveco/conntrack_exporter:0.1
```

Then open http://localhost:9318/metrics in your browser.

To change the listen port:

```
docker run -d --cap-add=NET_ADMIN --net=host --name=conntrack_exporter hiveco/conntrack_exporter:0.1 --listen-port=9101
```

Run with `--help` to see all available options.


## Building

Prerequisites:

* [Bazel](https://www.bazel.build/) (tested with v0.7.0)
* libnetfilter-conntrack-dev (Ubuntu/Debian: `apt-get install libnetfilter-conntrack-dev`)

conntrack_exporter builds as a mostly-static binary, only requiring that the `libnetfilter_conntrack` library is available on the system. To build the binary, run `make`. To build the `hiveco/conntrack_exporter` Docker image, run `make build_docker`.

NOTE: Building has only been tested on Ubuntu 16.04.


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

Why not? One difficulty is that `tcpstat` parses `/proc/net/tcp` to obtain its metrics, which can become slow on a busy server. In addition, there would be significant overhead for the Prometheus server to scrape and store the large amount of constantly-changing label:value pairs of metrics that such a busy server would expose. As stated in the [docs](https://github.com/prometheus/node_exporter/commit/e2163db0f7a8f16ba9f505d9ca72bc2c68696e7d#diff-04c6e90faac2675aa89e2176d2eec7d8R54) accompanying tcpstat, "the current version has potential performance issues in high load situations". So the Prometheus authors decided to expose only totals for each TCP state, which is quite a reasonable choice for the typical user.

conntrack_exporter exists to put that choice in the hands of the user. It is written in C++ (`node_exporter` is written in Golang) and instead of parsing `/proc/net/tcp`, it uses [libnetfilter_conntrack](https://www.netfilter.org/projects/libnetfilter_conntrack/) for direct access to the Linux kernel's connection table. This should make it reasonably fast even on busy servers, and allows more visibility into what's behind the summarized totals exposed by `tcpstat`.

### Should I run this on a server that listens for external Internet connections?

Probably not, since a large number of unique connecting clients will create many metric labels and your Prometheus instance may be overwhelmed. conntrack_exporter is best used with internal servers (like application servers behind a load balancer, databases, caches, queues, etc), since the total number of remote endpoints these connect to tends to be small and fixed (i.e. usually just the other internal services behind your firewall).

### I know some open connections were closed, why is `conntrack_closed_connections_total` not reporting them?

conntrack_exporter just exposes the system's connection table in a format Prometheus can scrape, and it's likely the closed connections are being dropped from the system table very quickly. It could be that this guage goes up for some short period and then goes back down again before your Prometheus server can scrape it.

Either increase the scrape frequency so Prometheus is more likely to notice the change, or increase how long the system "remembers" closed connections, which is controlled by `nf_conntrack_tcp_timeout_close` (this value is in seconds).

Check the current setting:
```
sysctl net.netfilter.nf_conntrack_tcp_timeout_close
```

Update it temporarily (lasts until next reboot):
```
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close=60
```

Update it permanently:
```
echo "net.netfilter.nf_conntrack_tcp_timeout_close=60" >> /etc/sysctl.conf
sysctl -p
```

**WARNING:** Raising this setting too high is not recommended, especially on high-traffic servers, because it'll overflow your system's connection table due to all the extra closed connections it has to keep track of.

Similar issues with other connection states (besides `closed`) might be resolved by updating the other `net.netfilter.nf_conntrack_tcp_timeout_*` settings as appropriate. Run `sysctl -a | grep conntrack | grep timeout` to see all available settings.

### It's great, but I wish it...

Please open a [new issue](https://github.com/hiveco/conntrack_exporter/issues/new).
