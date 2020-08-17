load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")
http_archive(
    name = "com_github_jupp0r_prometheus_cpp",
    strip_prefix = "prometheus-cpp-master",
    urls = ["https://github.com/jupp0r/prometheus-cpp/archive/master.zip"],
)

load("@com_github_jupp0r_prometheus_cpp//bazel:repositories.bzl", "prometheus_cpp_repositories")

prometheus_cpp_repositories()

load("//:repositories.bzl", "conntrack_exporter_dependencies")
conntrack_exporter_dependencies()
