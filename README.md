# TODO: update

# build-observer

`build-observer` is a tool to observe the build process of a project and create a log of all files that are read, written or executed during the build.

This log can then be used to create a Software Bill of Materials (SBOM) for the project.

> [!IMPORTANT]
> This is a preview software and is subject to change.

```
Usage:
build-observer -u user -- command [flags]

Examples:
sudo build-observer --user vagrant -- make -f Makefile.linux build-examples

Flags:
-h, --help            help for build-observer
-o, --output string   Output filename (default "build-observations.out")
-u, --user string     Run command as user
-v, --version         version for build-observer
```

### Requirements
- Linux kernel 4.9+ (for eBPF support)
- bpftrace 0.17.0+ (for eBPF support)
- build-observer needs to run as root to install eBPF program, but will drop privileges to the specified user to run the build command.

## Status: proof-of-concept implementation

This is a simple PoC of the build-observer concept that delegates the actual eBPF work to bpftrace.

Future work will move to C (bcc) + github.com/cilium/ebpf to simplify the
setup and requirements for end users.

There is also an existing implementation based on ptrace that might be
useful (but much less performant) on platforms without eBPF support.
