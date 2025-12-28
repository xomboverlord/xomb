# XOmB (Zombie) Exokernel

The XOmB Exokernel is a modern, multicore kernel designed to give the most flexibility to applications by leveraging modern hardware techniques and eschewing legacy designs all while fully supporting current applications. This system gives modern software a fighting chance to perform well for decades to come by allowing the user applications themselves decide on lower-level implementation details.

This Rust implementation is heavily based on the original D implementation written and designed by James Larkby-Lahet, wilkie, and Brian Madden at the University of Pittsburgh. This implementation takes off from where that project left off while also rewriting it in modern Rust.

## What is an exokernel?

From Wikipedia: (http://en.wikipedia.org/wiki/Exokernel)

> The idea behind exokernels is to force as few abstractions as possible on developers, enabling them to make as many decisions as possible about hardware abstractions. Exokernels are tiny, since functionality is limited to ensuring protection and multiplexing of resources, which are vastly simpler than conventional microkernels' implementation of message passing and monolithic kernels' implementation of abstractions.
>
> Applications may request specific memory addresses, disk blocks, etc. The kernel only ensures that the requested resource is free, and the application is allowed to access it. This low-level hardware access allows the programmer to implement custom abstractions, and omit unnecessary ones, most commonly to improve a program's performance. It also allows programmers to choose what level of abstraction they want, high, or low.

## Philosophy

TBD

## Software License

The XOmB kernel is licensed under the [WTFPL](LICENSE) and you can do whatever you want.

## Development

XOmB is mainly developed in Rust.

To build most kernel artifacts, just run `make`:

```shell
make
```

To run in Bochs, a slow but accurate debugger, you'll need a Multiboot2 version of the kernel. You build that with `make build-mb2`. And then you can run in Bochs with `make bochs`:

```shell
make build-mb2
make bochs
```

You may have more success with a bochs you build yourself. We use this configuration when building Bochs for our own use:

```
mkdir -p $HOME/Bochs/usr
./configure --prefix=$HOME/Bochs/usr --with-sdl2 --enable-debugger-gui --enable-debugger --enable-instrumentation --enable-smp --enable-x86-64 --enable-cpu-level=6 --enable-avx --enable-evex --with-x11
```

Running it with QEMU is a bit faster. You can also run the Multiboot2 version with that using `make qemu-mb2`. You can run a UEFI version with `make build-uefi` and `make qemu`, though you will need to ensure you have the OVMF libraries installed. If the script has trouble finding your OVMF install, supply its location with `OVMF_DIR`, `OVMF_CODE`, and `OVMF_VARS` variables before running `make`. When in doubt, peek at the `Makefile`.

```shell
make build-uefi
make qemu
```

## Kernel Documentation

The documentation describing the system at a somewhat high level is located in the `docs` path.

* [Main Description](docs/MAIN.md)
* [Memory Overview](docs/MEMORY.md)
* [Process Overview](docs/PROCESS.md)

And some interesting developer diaries exist for the different stages of development the kernel took:

* [Stage 1 Tasklist](docs/tasks/STAGE_1.md)

## Library OSes

TBD

## Acknowledgments

The following people made significant code contributions to the first XOmB and suitably encouraged this new incarnation:

* Lindsey Bieda
* Steve Klabnik
* Andrew Tribone

We are in the debt of Dr. Ahmed Amer-- systems professor, expert 'it depends' advocate, and steadfast voice of reason-- for being a great mentor to all of us through our systems journey.

## AI Development

This project was developed with assistance from the Claude AI agent as primarily an experiment to see how well an AI in late 2025 could handle the task of writing an exokernel while heavily supervised. It was very bad at it, but nonetheless managed to eventually miss enough rakes to produce something coherent after a lot of hand holding. It kept assuming in its drunken daydreams that problems were due to compiler or emulator bugs instead of its own incompetence. I can relate. Yet, when it was told to consider the (what feels like obvious) actual problem, it could course-correct adequately enough. Some of the structure it chose was eerily familiar... like... did it steal this from the original XOmB? Am I plagiarizing† myself? This all to say: some of this code is its hallucinations.

† Jury is still out about whether or not this is the right term. Maybe 'collective nonconscious' is more apt.
