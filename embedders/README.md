## Signal stack
Since we perform the memory tracking in a signal handler we need to take care 
of a couple of issues related to signals.


The stack available for signal handling comes from a different memory region, 
than regular stack, so that if the regular stack of a thread overflows we have
extra stack space to execute the signal handler.

Lucet allocates its own signal stack explicitly, with default size being 
`libc::SIGSTKSZ`. This constant differs depending on the environment you 
compile in (128KiB for macOS, 8KiB for our CI machines).
It turns out that 8K is not enough on debug builds and it overflows in certain
 situations.

Lucet used to overflow silently, but it was fixed around 0.5.1
https://rustsec.org/advisories/RUSTSEC-2020-0004

We can provide our own value to lucet and make it allocate a bigger stack.

Wasmtime is not setting its own signal stack, but uses whatever is there 
already (the one set in rust libstd), and this time it is not configurable.
Unfortunately this stack may also turn out to be too small, so we are adding 
our custom stack for wasmtime.
To prevent silent overflows we add a guard page below the stack 
(stack grows down on x86:
http://www.cs.miami.edu/home/burt/learning/Csc421.171/workbook/stack-memory.html
https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64
).

**Signal stacks are registered per thread**, but because **signal handlers are 
per process**, it is impossible to run tests with wasmtime embedder and with 
lucet embedder in parallel like cargo test is doing, because lucet's and 
wasmtime's handlers are interfering with each other leading to strange 
segfaults or deadlocks.

