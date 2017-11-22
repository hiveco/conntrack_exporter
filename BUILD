cc_binary(
    name = "conntrack_exporter",
    srcs = glob(["src/*.cc", "src/*h"]),
    #includes = ["src"],
    deps = [
        "@prometheus_cpp//:prometheus_cpp",
        "@libnetfilter_conntrack//:libnetfilter_conntrack",
    ],
    linkstatic=1,
    linkopts = [
        "-l/usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so",
    ],
)
