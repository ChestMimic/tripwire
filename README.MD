# Tripwire

Trigger a terminal command when a known process ID is no longer active

Currently Windows only

## Usage

`tripwire.exe <PID> [command]`

Tripwire will look for a matching process and wait for it to end

When the PID terminates, tripwire will send `[command]` to terminal
