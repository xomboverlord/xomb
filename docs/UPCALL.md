An upcall is an entrypoint to a Process. For more information about the semantics of a Process, see [PROCESS](PROCESS.md). An entrypoint is the instruction that is jumped to when yielding to the Process. Every Process has at least one valid upcall to be functional: the `onYield` upcall. This is the entrypoint when the Process is simply the target of a yield call. This contains the value of the instruction pointer that will be established as the kernel yields CPU control to that Process.

Only the Process itself or its owning parent can establish the upcalls for a Process. It does so via the `MAP_UPCALL` system call which sets the given address into the corresponding entry in the kernel's Process metadata.

The other type of upcall is `onFault` which occurs when a page fault happens during the runtime of the Process or when a different Process faulted on an address of a Resource owned by the targeted Process. This upcall also gets the `processId` of the Process active during the fault. It then also has the normal context of the fault available by the conventions available on the particular hardware.

Here are the available enumerated upcalls securely faciliated by the exokernel:

* `1`: `YIELD` - `onYield` upcall which is just a normal execution path.
* `2`: `FREE` - `onFree` upcall is a hint that the Process is about to be deallocated which can only be invoked by an owning Process.
* `3`: `FAULT` - `onFault` upcall happens on a page fault.
