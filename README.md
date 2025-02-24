# TODO: update

# build-observer

`build-observer` is a tool to observe the build process of a project and create a record of all files that are read, written or executed during the build.

This record can then be used to create a Software Bill of Materials (SBOM) for the project. 
See [sbom-observer](https://github.com/sbom-observer/observer-cli) for tooling and more information.

This repository contains the eBPF program and a Go wrapper to use it. Dependencies are kept to a minimum to keep the program as auditable as possible.

Check [releases](https://github.com/sbom-observer/build-observer/releases) for pre-compiled binaries and SBOMs.

## Usage
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

## Requirements
- Linux kernel 5.8+ (for eBPF support)
- build-observer needs to run as root to install eBPF program, but will drop privileges to the specified user to run the build command.

## Future work

This version should be production ready, and we welcome feedback and contributions.

Roadmap includes support for FreeBSD and Windows, probably using dtrace/ETW.

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

