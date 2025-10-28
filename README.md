## Driver Buddy Revolutions is an IDA Pro plugin that automates common Windows kernel driver research. 
Install it by copying DriverBuddyRevolutions.py into your plugins/ directory or running it as a script. 
Hotkey: Shift-A.

### What it does:
#### 1. IOCTL enumeration and scoring

Scans the driver’s code to recover possible IOCTL control codes without needing symbols.
For each IOCTL it decodes:

device type
access mask
function number
buffering method (METHOD_BUFFERED / METHOD_NEITHER / etc.)
Ranks each IOCTL with a rough “risk score,” prioritizing things like:
METHOD_NEITHER I/O (raw user pointers)
FILE_ANY_ACCESS (no access check)
large/custom device types / high function ranges
Saves a timestamped text file of all discovered IOCTLs.

Generates an optional C stub that calls every discovered IOCTL via DeviceIoControl.

#### 2. Dispatch handler discovery

Tries to locate DriverEntry and, if there’s a trampoline, the “real” driver entry.
Heuristically identifies the driver’s IRP_MJ_DEVICE_CONTROL / IRP_MJ_INTERNAL_DEVICE_CONTROL dispatch routines by walking how the driver sets up its driver object.

Tries alternative heuristics (control-flow graph / structure offset patterns) if the classic pattern isn’t obvious.
Labels the candidates directly in IDA (renames things like DispatchDeviceControl when it’s confident).

#### 3. Pool tag extraction

Extracts per-call-site pool tags from calls like ExAllocatePoolWithTag, ExAllocatePool2, etc.
Associates each tag with the function(s) that allocate with it.
Dumps a timestamped text file of all tags found.

#### 4. Device name discovery

Scrapes both on-disk strings and IDA’s internal string table for things that look like device names and symbolic links:
\Device\...
\DosDevices\...
\??\...

Handles both ASCII and UTF-16LE inline strings, and tries to skip obvious filler like AAAA....
Reports likely \\.\DeviceName-style handles the driver might expose.

#### 5. Heuristics for interesting functions and behavior

The plugin walks all functions and applies lightweight checks, especially inside IOCTL handlers:

User copy without validation
Flags calls like memcpy, RtlCopyMemory, etc. where it doesn’t see nearby bounds/probing (e.g. ProbeForRead, integer-safety helpers) and where the call seems reachable from the IOCTL dispatch path.
Allocation size trust
Notes pool allocations (ExAllocatePool*) that appear to take sizes straight from user-controlled code paths without obvious integer-safety or bounds checks.
Privilege / policy checks
Looks for dangerous kernel APIs (mapping physical memory, section mapping, privilege checks, etc.) that are called from an IOCTL handler without SeAccessCheck/SeSinglePrivilegeCheck-style gating.
IRQL misuse hints
Looks for suspicious mixes like calling pageable / Zw* / mapping routines around IRQL-sensitive operations without obvious IRQL management, or touching MDLs / usermode mappings in a way that suggests “this might be callable at the wrong IRQL”.
Direct low-level instructions
Tags functions that execute instructions like wrmsr / rdmsr / rdpmc (these are marked “High”), because those are often abused in ring-0 implants and tuning drivers.
All of those findings are collected, assigned a severity (“Low / Medium / High / Critical”), and displayed in an interactive chooser window inside IDA. Double-clicking a row jumps straight to the EA that triggered the finding.

#### 6. Taint call tracing

Starts at each IOCTL handler.
Walks the call graph outward up to a configurable depth.
Records any path that eventually hits a known “sink” (e.g. raw memory copies, physical memory access, mapping I/O space).
Outputs those call chains (Handler → … → memcpy) so you can see dataflow hot paths without manually stepping through 5 layers of helpers.

#### 7. Export audit

Lists exported symbols from the driver.
Notes which of those exports appear to be referenced internally.
Gives you a view of whether the driver exposes callable kernel entry points beyond the standard dispatch table (miniports, filters, etc., sometimes do this).

#### 8. Stack / allocation usage

Greps for use of _alloc / _malloc patterns.
Flags functions that dynamically carve large stack frames or use large inline buffers.

#### 9. Reporting

On every run it writes timestamped artifacts to your working directory:

*-IOCTLs.txt
All discovered IOCTLs with decoded fields, severity labels, and reasons.
*-PoolTags.txt
All pool tags and which functions allocate with them.
*-DriverBuddyRevolutions_full_autoanalysis.txt
Human-readable log of everything it found (driver type, entry, device names, IOCTLs, heuristics, etc.).
*-DriverBuddyRevolutions_report.html
Clickable HTML summary. The report links EAs back into IDA via ida://jump?ea=..., so you can browse findings like a mini audit dashboard.
*-DriverBuddyRevolutions_findings.json
Structured dump of all findings (IOCTL metadata, heuristics, taint paths, etc.) for scripting or feeding into other tooling.
*-ioctl_pocs.c
A generated C with one DeviceIoControl call per IOCTL code you still have to pick the right device path and compile it yourself — but it’s useful for quickly fuzzing/probing.

See it in action here (In IDA Pro)
<img src="https://i.imgur.com/U2ULhwD.png">

And in example the HTML report:
<img src="https://i.imgur.com/Hsx54Xn.png">
