A Process is just a page table. It is a PML4 page table that is placed as the current page table (via CR3 on x86-64) when the Process is to be run. Any Resource that is accessible by a Process is any Resource that is mapped into that Process virtual address space via that root page table. The kernel maintains the allocated Process structures as leaves in a `PML3` space off of `PML4[507]`. Even though a Process is a root page table (PML4), they are stored as PML2 nodes within this Process mapping space. That means the kernel can be aware of a total of 262K active processes and be able to view and manipulate the Process root page table's PML4 and PML3 entries. In order for the kernel to manipulate the PML2 or PML1 entries of a non-active Process, the kernel has to context switch to the Process first, and perhaps context switch back before returning. This means one Process manipulating another Process address space in this way would be a relatively expensive operation since it would incur a TLB flush in most cases.

These Process objects are otherwise handled the same way as any Resource (see [RESOURCE.md](RESOURCE.md) for more information about these primitives.) A Process has an identifier (a `processId`) that is constructed as the kernel-space virtual address of that root page table from within that `PML4[507]` virtual space.

When a process wants to create a child process, it simply has the kernel create a process page table (a PML4) from the given physical page. It will map that process root page table as an intermediate page table in the address space of the calling Process to the virtual address desired by the calling Process. From here, the parent Process will need to allocate the subsequent Resource for the child Process that will contain the code and data for that eventual program. It then grants each Resource to the child Process. Then it optionally changes the owner to that child Process so that this Process can further affect its own page table on its own. It can then yield to the child Process.

Yielding to a process is just a system call (`YIELD_PROCESS`) to switch address spaces to the address space of the given process. The process is identified by its root page table in memory which is typically called `processId`. So, yield takes one argument: The `processId`, which is the virtual address of a process's root page table from within the kernel's process map. The yield call is used for cooperative scheduling. Preemption is done by a user process via a libos process scheduler that listens to the system timer. The kernel does not implement preemption.

There is no `fork` action in the exokernel proper. Implementing a `fork` semantic would just be to create a Process and then grant each Resource to the new process. Any extra semantics one wishes to impose to satisfy whatever definition of 'forking' an OS has in mind is up to that library OS process implementation.

Any parent Process "owns" the child Process. Ownership is related to the flags set when mapping in that child Process root page table into the parent Process. That page table entry that points to the child's would-be PML4 is marked with the `Owner` flag. When the kernel wants to validate ownership (the parent status) of the calling Process, it looks at the Process-local Resource pointed to via the `processAddress` and looks for the `Owner` flag and also looks to see that the physical page pointed to by that page table entry is the same as that PML4 of the child Process via the `processId` and walking the structure within the process map (`PML4[507]`) in the kernel's memory. They need to match to confirm that relationship.

Since the kernel maintains the mapping of Process PML4s as PML2s off of `PML4[507]`, the leaves of this virtual address space point to the potential PML2s of that child Process. It is worth noting that when a Process is allocated, it is *only* an empty PML4. It is up to library OSes in userspace to denote what the page table structure of a Process actually looks like. However, considering a saturated page table structure for a hypothetical Process, the kernel mapping can always manipulate the PML2s of any running Process. This means that granting any PML2 (or larger) Resource to another Process can be done without context switching away from the granting Process. It also means that loading a new Process (say from a shell application) can be done by:

* Allocating a PML4 via `ALLOC_PROCESS` and mapping it into a PML2 of the calling parent Process.
* Allocating a PML3 page in that child Process by allocating the PML1 in the appropriate place in the parent Process.
* Allocating a PML2-sized Resource in the parent at some PML2 in the calling parent Process.
* Loading the executable code into the PML2 by allocating the necessary page structure and leaf pages and filling them with executable and data content from a binary executable.
* Granting the PML2-sized Resource to the child Process via `GRANT_RESOURCE`. This affectively updates the PML3 in the child to point to the PML2 root of the calling Process.
* Changing the owner for this Resource via `CHOWN_RESOURCE` which now gives ownership to the child Process.

All of these require absolutely no context switching and can be done with the global page table mapping in the kernel. It possible to grant a PML1-sized (2MB on x86-64) Resource to another Process and modify the page table of that Process without a context switch. With very careful Resource management, most metadata and Process page structures are visible from the global page table available to the kernel and manipulation can be done cheaply.

The kernel also maintains a backward reference that maps physical addresses of the root page tables to Process metadata. This metadata contains the actual `processId` that would normally be used and also the kernel-aware upcalls. The `onYield` upcall and `onFree` upcall are virtual addresses that will be the instruction pointers upon yielding to the Process. Each of these upcalls will pass a single argument of the last running `processId`. The `onFree` upcall occurs when a parent Process is hinting that it is about to deallocate the Process page table so the child Process can responsibly respond and deallocate its own resources. Generally, yielding back to the calling Process is expected. For more information about upcalls refer to [UPCALL](UPCALL.md).

The kernel system calls related to process allocation and mapping have an enumerated return value to indicate the error or 0 if successful. The `ProcessError` error codes are as follows:

* `0`: `SUCCESS` - Successful operation with no other return value expected.
* `1`: `INVALID_FLAGS` - Invalid flags were specified.
* `2`: `NOT_FREE` - The physical page is not free and cannot be used to allocate a structure.
* `4`: `INVALID_SOURCE` - The given virtual address for the resource is invalid. When allocating, this means that the `resourceAddress` specified is not free. On other calls, it means there's no valid resource at `resourceAddress`.
* `5`: `INVALID_TARGET` - The processId to yield to was invalid.
* `6`: `NO_ROOM` - We reached the maximum number of processes.

The kernel offers several primitive functions to faciliate the creation and control of processes:

* `ALLOC_PROCESS(physicalAddress, processAddress) -> ProcessError | processId` - Spawns a child process that will be mapped to the provided userspace address of the calling Process. Returns the `processId`, which is a virtual address in kernel space that, via the recursive page table entry (`PML4[510]`), points to the root page table of the new process. The `processAddress` needs to be a valid page table entry to attach the root page table for the child Process using the recursive entry `PML4[510]` to do so. Fails with `INVALID_TARGET` if the page table structure does not exist or not owned by the calling Process. This fails with `NO_ROOM` if there are no available processes left in the system because the kernel's process map is full. This fails with `NOT_FREE` if the `physicalAddress` specified is not actually free.
* `YIELD_PROCESS(processId) -> ProcessError` - Cooperatively yields to the given Process. The `onYield` upcall of the target Process will be passed the calling Process `processId`. Effectively, this swaps the current root page table (PML4 via CR3) to the one for the given process. The process has to deal with restoring its own state. There's no context being stored because the kernel is effectively stateless except for maintaining access to all address spaces. On success, this function never returns. If the `processId` is in any way invalid, it will return with the `INVALID_TARGET` error.
* `FREE_PROCESS(processId, processAddress) -> ProcessError` - Yields to a child process that was previously allocated via an early `ALLOC_PROCESS` call to allow it to deal with closing itself. It calls the `onFree` upcall while passing the current Process `processId`. The calling Process might expect that the target Process yield back. Fails with `INVALID_SOURCE` if the calling Process is not the parent of the given Process (that is, `processAddress` does not point to the same physical page as the PML4 within the address space rooted at `processId`). It does not return on success. The parent Process effectively frees a child Process on its own during its next quantum by deallocating all pages of the child Process.

The kernel has the following check (which is identical to the one for checking if a Process owns a Resource) of whether or not the calling Process is the parent of the given Process, which it checks on the Process free operation:

* `is_mapped(processId, processAddress) -> boolean` - This looks at the `processId` and ensures that it is a virtual address that runs through the kernel's Process map. Let's say that we maintain a mapping of all processes on `PML4[507]`, so the 507th index of the root page table points to a PML3 that contains, as leaves of the tree, the root page tables of all known Process objects. We can then tell very easily if `processId` is a virtual address that uses the recursive entry (`PML4[510]`) to point to the physical page of the Process root. That physical page must be the same one pointed to by the given `processAddress`. We also verify that the `processAddress` is not in higher memory, which is always owned by privileged kernel code. If all of these hold true, the current calling Process owns the given Process as it is the parent of the given Process.

The kernel uses this procedure to create a Process (`ALLOC_PROCESS`):

* Marks the given `physicalAddress` allocated (and otherwise fails with `NOT_FREE`)
* Uses this physical page as the root page table of the child Process.
* Maps this root page table into the calling Process in the page table entry it specified.
* It marks this page table entry with the `Owner` flag.
* It maps this root page table into the Process map (`PML4[507]`) such that it is a PML2 there.
* It determines the `processId` which is the virtual address that points to that PML2 in the Process map.
* It stores this `processId` along with other initial metadata as the value in the Process hash using the physical address as the key. This can be used to forcibly kill a child Process when the owning parent Process is forcibly killed itself or crashes. Other metadata contained within here are the destination addresses of upcalls.
* It returns the `processId` to the calling Process.

The kernel uses this procedure to yield to a Process (`YIELD_PROCESS`):

* Validates that `processId` is a virtual address that points into the Process map at `PML4[507]`. Fails with `INVALID_TARGET` if it is not.
* Parses the `processId` to determine the physical address of that root page table.
* Pulls out the process metadata from the Process hash.
* Switches the root page table of the system to this one.
* Flushes any virtual address translation caches (TLB, etc)
* Returns to the `onYield` upcall by looking it up within the process metadata.

The kernel uses this procedure to free a Process (`FREE_PROCESS`):

* Validates that `processId` is a virtual address that points into the Process map at `PML4[507]`. Fails with `INVALID_SOURCE` if it is not.
* Parses the `processId` to determine the physical address of that root page table.
* Validates ownership of the calling Process by examining for equality the physical page pointed to by the given `processAddress` is the same as the root page table of the given Process. If `processAddress` is not a valid page table entry or does not equal the expected address, it fails with `INVALID_SOURCE`.
* Yields to the `onFree` upcall of the other process while passing the calling Process `processId`.
* Does not return to the calling Process. The calling Process must understand that it needs to listen to a timer to preempt and properly delete the child if it wants to ensure that the child Process is gone.
* **Note**: When the calling Process regains control, it can just remove the root page table of the child Process, effectively stopping it from existing. The `FREE_PROCESS` call is just here to provide a kernel means of securely calling the `onFree` upcall.
