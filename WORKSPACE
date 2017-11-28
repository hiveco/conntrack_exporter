git_repository(
    name = "prometheus_cpp",
    remote = "https://github.com/jupp0r/prometheus-cpp.git",
    commit = "871a7673772b266135cc8422490578da1cf63004",
)

load("@prometheus_cpp//:repositories.bzl", "prometheus_cpp_repositories")
prometheus_cpp_repositories()

load("//:repositories.bzl", "conntrack_exporter_dependencies")
conntrack_exporter_dependencies()
