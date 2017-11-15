# Tripwire
Trigger a shutdown command when a known process ID is no longer active
Currently Windows only

## Usage
tripwire.exe <PID>
	PID should be any positive number representing an active Windows process

Tripwire will look for a matching process and wait for it to end
When the PID terminates, tripwire will send *shutdown -s -t 60* to system
