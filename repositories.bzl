load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

def libnetfilter_conntrack_repositories():

    BUILD = """
cc_library(
    name = "libnetfilter_conntrack",
    includes = ["."],
    visibility = ["//visibility:public"],
)
"""

    # This requires libnetfilter-conntrack-dev to be installed on Ubuntu/Debian
    native.new_local_repository(
        name = "libnetfilter_conntrack",
        path = "/usr/include",
        build_file_content = BUILD,
    )


def argagg_repositories():

    BUILD = """
cc_library(
    name = "argagg",
    hdrs = ["include/argagg/argagg.hpp"],
    includes = ["include"],
    visibility = ["//visibility:public"],
)
"""

    new_git_repository(
        name = "argagg",
        remote = "https://github.com/vietjtnguyen/argagg.git",
        commit = "4c8c86180cfafb1448f583ed0973da8c2f559dd6",
        build_file_content = BUILD,
    )


def conntrack_exporter_dependencies():
    libnetfilter_conntrack_repositories()
    argagg_repositories()
