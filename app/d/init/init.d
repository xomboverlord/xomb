/* xsh.d

   XOmB Native Shell

*/

module init;

import embeddedfs;

import user.syscall;
import user.environment;

import libos.fs.minfs;

import console;
import libos.keyboard;

import user.keycodes;

import libos.libdeepmajik.threadscheduler;

import libos.elf.loader;
import mindrt.util;


void main() {

	// create heap gib?

	// initialize userspace console code
	Console.initialize(cast(ubyte*)(2*oneGB));
	Keyboard.initialize(cast(ushort*)(3*oneGB));

	EmbeddedFS.makeFS();

	// say hello
	Console.backcolor = Color.Black; 
	Console.forecolor = Color.Green;

	Console.putString("\nWelcome to XOmB\n");
	Console.putString(  "-=-=-=-=-=-=-=-\n\n");
	
	Console.backcolor = Color.Black; 
	Console.forecolor = Color.LightGray;

	// yield to xsh
	AddressSpace xshAS = createAddressSpace();	
	
	map(xshAS, EmbeddedFS.shellAddr(), cast(ubyte*)oneGB, AccessMode.Writable);

	map(xshAS, cast(ubyte*)(2*oneGB), cast(ubyte*)(2*oneGB), AccessMode.Writable);
	map(xshAS, cast(ubyte*)(3*oneGB), cast(ubyte*)(3*oneGB), AccessMode.Writable);

	yieldToAddressSpace(xshAS);

	Console.putString("Done"); for(;;){}
}
