cc_binary(
    name = "conntrack_exporter",
    srcs = glob(["src/*.cc", "src/*h"]),
    deps = [
        "@com_github_jupp0r_prometheus_cpp//pull",
        "@libnetfilter_conntrack//:libnetfilter_conntrack",
        "@argagg//:argagg",
    ],
    linkstatic=1,
    linkopts = [
        "-l/usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so",
    ],
)
