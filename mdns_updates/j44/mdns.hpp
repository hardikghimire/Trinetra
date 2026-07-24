#ifndef MDNS_HPP
#define MDNS_HPP

#include <string>

// Parsed identity info for one LAN host, learned passively off mDNS
// (UDP 224.0.0.251:5353) traffic seen while Shiv is running.
struct MdnsDeviceInfo {
    std::string hostname;   // e.g. "Android-7"  (".local" stripped)
    std::string name;       // e.g. "Hridaya"     (friendly/instance name, if any)
};

// Starts a background listener that joins the mDNS multicast group on
// `interface` and passively collects device-identity info for the whole
// life of the scan. Safe to call once per process — a second call while
// already running is a no-op. Non-fatal on failure (no permission,
// interface down, etc.) — the scan just proceeds without device info.
void start_mdns_listener(const std::string& interface);

// Stops the listener thread and releases its socket. Call exactly once,
// after all scanning for the run has finished, right before final output
// is written (so results are as complete as possible).
void stop_mdns_listener();

// Looks up whatever has been learned so far about `ip` (dotted-quad
// string). Returns an MdnsDeviceInfo with both fields empty if nothing
// has been captured for that IP.
MdnsDeviceInfo get_mdns_device_info(const std::string& ip);

// Convenience formatter matching Shiv's report style:
//   both known    -> "Android-7 (Hridaya)"
//   hostname only -> "Android-7"
//   name only     -> "Hridaya"
//   neither       -> ""   (caller should skip printing the Device line)
std::string format_mdns_device(const MdnsDeviceInfo& info);

#endif // MDNS_HPP
