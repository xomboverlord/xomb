XOmB is an exokernel.

An exokernel is a type of kernel that provides a very minimal abstraction. It multiplexes hardware resources in userspace in the form of 'Library OSes'. These library OSes provide the implementations necessary to drive devices for the needs of applications that are linked to them.

The role of the privileged kernel is just what is necessary to secure access to resources. All responsibility for resource management and decisions based around how to effectively use those resources is relegated to the library OSes and the needs of each application.

In XOmB, the main mechanism to secure access to resources is the paging system. Resources are memory mapped whenever possible and then access to resources are given to applications, through their library OSes, via the paging system. For instance, access to the network card might be given by mapping the register space onto a region of memory and then placing that into the memory space of a library OS. If an application might only want to read that memory space, it could have those pages mapped into their virtual address space with a read-only flag set.

The exokernel will make extensive use of any optimization or technique available to it in order to most efficiently use virtual memory to provide access and access control of such resources. For example, in x86-64, the kernel would certainly make use of 'superpages', which are large virtual memory allocations made by shallow page table entries marked as terminating at higher levels. These pages, then, represent multiples of the normal page size in terms of their allocations. It might even be beneficial to use gigabyte-large virtual address spaces to very efficently map out large linear address spaces for application use.

Updating access controls (or revoking access) will be as simple as updating the page table entries themselves and flushing any cache or TLB that might still be referencing it. Multiplexing a scarce resource might entail atomically updating access in one page table entry with another entry within a different process virtual address space to, thus, atomically swap such access. Though, the atomicity is still affected by our ability to flush relevant caches in time. Therefore, it is still rather important to consider the scheduling of these actions when requested by each application.

The main kernel maintains the root page table. The root page table is effectively set at the start and not changed. Within the page table structure, the entries within maintain the state of the system and the current process or processes and the current resources. Each Process is effectively represented as a page table entry and a slightly lower level. So, if we assume a five-level paging system, like on modern x86-64, the root page table is created and maintained by the kernel and it maps into that as a page table entry a pointer to the root page table of a process. The process, then, in turn owns its page table and maps in resources via kernel primitive functions and system calls. Once resources are securely provisioned to the process, the process can effectively do anything the page tables permit. Resources are, like processes, represented by slightly lower level page table structures that are able to be mapped into the process page table (which in turn can be placed into the system address space via the kernel's root page table.)

To summarize the kernel actions we need to make this kernel operate:

- Create a process which is basically a virtual address space (which is represented as a page table entry and is the main data structure that represents a process or process group)
- Allocate a resource (which is represented as a page table entry)
- Attach a resource to a virtual address space (link a page table entry in a 'process' to the page table entry serving as the root of a resource)
- Update the access of a resource (update a page table entry in a 'process')
- Atomically swap access to a resource (update two 'process' structures by nulling a resource entry while adding it to another)

These operations need to be verifiable in our kernel. Applications rely on these operations being secure.

The unanswered questions so far have to do with scheduling and preemption.

For stage 1, we will have a non-preemptive single process kernel to sidestep solving these problems.
