//! WASI-specific async DNS resolution using native WASIp2 interfaces
//!
//! This resolver attempts to use WASI's native DNS resolution first, with fallback
//! to hardcoded IP addresses for known hosts. IPv6 addresses are filtered out
//! to ensure WebRTC/STUN compatibility, as these protocols typically require IPv4
//! in the current WASI environment.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(target_os = "wasi")]
use wasi::sockets::{
    instance_network::instance_network,
    ip_name_lookup::{resolve_addresses, ResolveAddressStream},
    network::IpAddress,
};

#[cfg(target_os = "wasi")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "wasi")]
use std::task::Waker;

/// Async DNS resolution for WASI using native WASIp2 ip-name-lookup interface
pub(crate) fn resolve_dns_async(
    host: String,
) -> impl Future<Output = io::Result<std::vec::IntoIter<SocketAddr>>> {
    WasiDnsResolver::new(host)
}

struct WasiDnsResolver {
    host: String,
    state: ResolverState,
}

#[cfg(target_os = "wasi")]
enum ResolverState {
    Parsing,
    Resolving {
        hostname: String,
        port: u16,
    },
    WasiResolving {
        stream: ResolveAddressStream,
        port: u16,
        addresses: Vec<IpAddr>,
        pollable: Option<wasi::io::poll::Pollable>,
        waker_bridge: Option<Arc<WakerBridge>>,
        poll_count: u32,
    },
    Done(Vec<SocketAddr>),
    Error(io::Error),
}

#[cfg(target_os = "wasi")]
struct WakerBridge {
    waker: Mutex<Option<Waker>>,
    is_ready: Mutex<bool>,
}

#[cfg(target_os = "wasi")]
impl WakerBridge {
    fn new() -> Self {
        Self {
            waker: Mutex::new(None),
            is_ready: Mutex::new(false),
        }
    }

    fn set_waker(&self, waker: Waker) {
        if let Ok(mut w) = self.waker.lock() {
            *w = Some(waker);
        }
    }

    fn wake(&self) {
        if let Ok(mut ready) = self.is_ready.lock() {
            *ready = true;
        }
        if let Ok(waker_guard) = self.waker.lock() {
            if let Some(waker) = waker_guard.as_ref() {
                waker.wake_by_ref();
            }
        }
    }

    fn is_ready(&self) -> bool {
        self.is_ready.lock().map(|r| *r).unwrap_or(false)
    }

    fn reset(&self) {
        if let Ok(mut ready) = self.is_ready.lock() {
            *ready = false;
        }
    }
}

#[cfg(not(target_os = "wasi"))]
enum ResolverState {
    Parsing,
    Resolving { hostname: String, port: u16 },
    Done(Vec<SocketAddr>),
    Error(io::Error),
}

impl WasiDnsResolver {
    fn new(host: String) -> Self {
        Self {
            host,
            state: ResolverState::Parsing,
        }
    }

    #[cfg(target_os = "wasi")]
    fn cleanup_wasi_resources(&mut self) {
        if let ResolverState::WasiResolving {
            pollable,
            waker_bridge,
            ..
        } = &mut self.state
        {
            // Clean up WASI resources to avoid crashes during drop
            *pollable = None;
            *waker_bridge = None;
        }
    }
}

#[cfg(target_os = "wasi")]
impl Drop for WasiDnsResolver {
    fn drop(&mut self) {
        self.cleanup_wasi_resources();
    }
}

impl Future for WasiDnsResolver {
    type Output = io::Result<std::vec::IntoIter<SocketAddr>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Extract hostname once to avoid borrowing issues
            let hostname = self.host.split(':').next().unwrap_or("").to_string();

            match &mut self.state {
                ResolverState::Parsing => {
                    // Parse the host:port string directly here
                    let (hostname, port) = if let Some(pos) = self.host.rfind(':') {
                        let hostname = &self.host[..pos];
                        let port_str = &self.host[pos + 1..];

                        match port_str.parse::<u16>() {
                            Ok(port) => (hostname.to_string(), port),
                            Err(_) => {
                                self.state = ResolverState::Error(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "Invalid port number",
                                ));
                                continue;
                            }
                        }
                    } else {
                        self.state = ResolverState::Error(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Missing port number",
                        ));
                        continue;
                    };

                    // Check if hostname is already an IP address
                    if let Ok(ip) = hostname.parse::<IpAddr>() {
                        let addr = SocketAddr::new(ip, port);
                        self.state = ResolverState::Done(vec![addr]);
                        continue;
                    }

                    // Start DNS resolution for hostname
                    self.state = ResolverState::Resolving { hostname, port };
                    continue;
                }
                ResolverState::Resolving { hostname, port } => {
                    // Try to use WASI DNS resolution
                    #[cfg(target_os = "wasi")]
                    {
                        // Only log DNS resolution for non-google/cloudflare servers to reduce noise
                        if !hostname.contains("google.com") && !hostname.contains("cloudflare.com")
                        {
                            eprintln!("🌐 Attempting WASI DNS resolution for: {}", hostname);
                        }
                        match attempt_wasi_dns_resolution(hostname, *port) {
                            Ok(stream_state) => {
                                if !hostname.contains("google.com")
                                    && !hostname.contains("cloudflare.com")
                                {
                                    eprintln!("✅ WASI DNS resolution started for: {}", hostname);
                                }
                                self.state = stream_state;
                                continue;
                            }
                            Err(e) => {
                                eprintln!(
                                    "❌ WASI DNS resolution failed immediately for {}: {}",
                                    hostname, e
                                );
                                self.state = ResolverState::Error(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("DNS resolution failed: {}", e),
                                ));
                                continue;
                            }
                        }
                    }

                    #[cfg(not(target_os = "wasi"))]
                    {
                        self.state = ResolverState::Error(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "WASI DNS resolution only available on WASI",
                        ));
                        continue;
                    }
                }
                #[cfg(target_os = "wasi")]
                ResolverState::WasiResolving {
                    stream,
                    port,
                    addresses,
                    pollable,
                    waker_bridge,
                    poll_count,
                } => {
                    // Initialize waker bridge if not already done
                    if waker_bridge.is_none() {
                        let bridge = Arc::new(WakerBridge::new());
                        bridge.set_waker(cx.waker().clone());
                        *waker_bridge = Some(bridge.clone());

                        // Try to get the pollable for this stream if we haven't already
                        if pollable.is_none() {
                            let p = stream.subscribe();
                            if !hostname.contains("google.com")
                                && !hostname.contains("cloudflare.com")
                            {
                                eprintln!(
                                    "📡 Created WASI pollable for async DNS for {}",
                                    &hostname
                                );
                            }
                            *pollable = Some(p);
                        }
                    } else if let Some(bridge) = waker_bridge.as_ref() {
                        // Update the waker in case the task was moved
                        bridge.set_waker(cx.waker().clone());
                    }

                    // Check if the pollable is ready using WASI's poll
                    if let Some(p) = pollable.as_ref() {
                        let poll_result = wasi::io::poll::poll(&[p]);
                        if !poll_result.is_empty() {
                            if !hostname.contains("google.com")
                                && !hostname.contains("cloudflare.com")
                            {
                                eprintln!("📡 WASI pollable is ready for {}", &hostname);
                            }
                            if let Some(bridge) = waker_bridge.as_ref() {
                                bridge.wake();
                            }
                        }
                    }

                    *poll_count += 1;

                    // Check if we should give up on WASI DNS and fall back
                    let should_fallback = if hostname.contains("livekit.cloud") {
                        // For LiveKit domains, be more patient - try for 10 polls or if the pollable is ready
                        *poll_count > 10
                            || (waker_bridge.as_ref().map(|b| b.is_ready()).unwrap_or(false)
                                && *poll_count > 3)
                    } else {
                        // For other domains, try for 3 polls or if the pollable is ready
                        *poll_count > 3
                            || (waker_bridge.as_ref().map(|b| b.is_ready()).unwrap_or(false)
                                && *poll_count > 1)
                    };

                    if should_fallback {
                        if !hostname.contains("google.com") && !hostname.contains("cloudflare.com")
                        {
                            eprintln!("WASI DNS taking too long (poll count: {}), falling back to hardcoded addresses for {}", poll_count, &hostname);
                        }

                        // Clean up WASI resources before falling back
                        *pollable = None;
                        *waker_bridge = None;

                        if let Some(fallback_addrs) = get_fallback_address(&hostname) {
                            let socket_addrs = fallback_addrs
                                .into_iter()
                                .map(|ip| SocketAddr::new(ip, *port))
                                .collect();
                            self.state = ResolverState::Done(socket_addrs);
                            continue;
                        } else {
                            self.state = ResolverState::Error(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("WASI DNS resolution timed out for {} and no fallback available", &hostname),
                            ));
                            continue;
                        }
                    }

                    // Poll the WASI resolver stream for more addresses
                    match stream.resolve_next_address() {
                        Ok(Some(ip_addr)) => {
                            let ip = convert_wasi_ip_to_std(ip_addr);
                            // Filter out IPv6 addresses for WebRTC/STUN compatibility
                            match ip {
                                IpAddr::V4(_) => {
                                    addresses.push(ip);
                                    eprintln!(
                                        "✅ WASI DNS resolved {} to {} (IPv4)",
                                        &hostname, ip
                                    );
                                }
                                IpAddr::V6(_) => {
                                    if !hostname.contains("google.com")
                                        && !hostname.contains("cloudflare.com")
                                    {
                                        eprintln!("⚠️ Filtering out IPv6 address {} for {} (WebRTC/STUN requires IPv4)", ip, &hostname);
                                    }
                                }
                            }
                            // Reset the waker bridge since we got a result
                            if let Some(bridge) = waker_bridge.as_ref() {
                                bridge.reset();
                            }
                            // Continue immediately to check for more addresses
                            continue;
                        }
                        Ok(None) => {
                            // No more addresses, we're done
                            if addresses.is_empty() {
                                eprintln!(
                                    "WASI DNS returned no addresses for {}, falling back",
                                    &hostname
                                );
                                // Clean up WASI resources before falling back
                                *pollable = None;
                                *waker_bridge = None;

                                // Fall back to hardcoded if no addresses were resolved
                                if let Some(fallback_addrs) = get_fallback_address(&hostname) {
                                    let socket_addrs = fallback_addrs
                                        .into_iter()
                                        .map(|ip| SocketAddr::new(ip, *port))
                                        .collect();
                                    self.state = ResolverState::Done(socket_addrs);
                                } else {
                                    self.state = ResolverState::Error(io::Error::new(
                                        io::ErrorKind::NotFound,
                                        "No DNS results and no fallback available",
                                    ));
                                }
                            } else {
                                let ipv4_count = addresses.iter().filter(|ip| ip.is_ipv4()).count();
                                eprintln!(
                                    "✅ WASI DNS completed for {} with {} IPv4 addresses (filtered out any IPv6)",
                                    &hostname,
                                    ipv4_count
                                );

                                if ipv4_count == 0 {
                                    eprintln!("⚠️ No IPv4 addresses available after filtering, falling back to hardcoded");
                                    // Clean up WASI resources before falling back
                                    *pollable = None;
                                    *waker_bridge = None;

                                    if let Some(fallback_addrs) = get_fallback_address(&hostname) {
                                        let socket_addrs = fallback_addrs
                                            .into_iter()
                                            .map(|ip| SocketAddr::new(ip, *port))
                                            .collect();
                                        self.state = ResolverState::Done(socket_addrs);
                                    } else {
                                        self.state = ResolverState::Error(io::Error::new(
                                            io::ErrorKind::NotFound,
                                            "No IPv4 addresses found and no fallback available",
                                        ));
                                    }
                                } else {
                                    let socket_addrs = addresses
                                        .iter()
                                        .filter(|ip| ip.is_ipv4()) // Double-check IPv4 filtering
                                        .map(|ip| SocketAddr::new(*ip, *port))
                                        .collect();
                                    self.state = ResolverState::Done(socket_addrs);
                                }
                            }
                            continue;
                        }
                        Err(wasi::sockets::network::ErrorCode::WouldBlock) => {
                            // Check if our background thread has signaled that the pollable is ready
                            if let Some(bridge) = waker_bridge.as_ref() {
                                if bridge.is_ready() {
                                    eprintln!(
                                        "📡 WASI pollable signaled ready for {}, retrying...",
                                        &hostname
                                    );
                                    bridge.reset(); // Reset for next poll
                                    continue; // Try resolve_next_address again
                                }
                            }

                            // For LiveKit domains, be more patient and wait for the pollable
                            if hostname.contains("livekit.cloud") && *poll_count < 8 {
                                eprintln!("⏳ WASI DNS would block for LiveKit domain {}, poll count: {}, waiting for pollable...", &hostname, *poll_count);
                                return Poll::Pending;
                            } else if *poll_count < 3 {
                                eprintln!("⏳ WASI DNS would block for {}, poll count: {}, waiting for pollable...", &hostname, *poll_count);
                                return Poll::Pending;
                            } else {
                                // WASI DNS would block - fall back immediately for non-LiveKit or after retries
                                eprintln!("⚠️ WASI DNS would block for {}, falling back to hardcoded addresses immediately", &hostname);

                                // Clean up WASI resources before falling back
                                *pollable = None;
                                *waker_bridge = None;

                                if let Some(fallback_addrs) = get_fallback_address(&hostname) {
                                    let socket_addrs = fallback_addrs
                                        .into_iter()
                                        .map(|ip| SocketAddr::new(ip, *port))
                                        .collect();
                                    self.state = ResolverState::Done(socket_addrs);
                                    continue;
                                } else {
                                    self.state = ResolverState::Error(io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        format!(
                                            "WASI DNS would block for {} and no fallback available",
                                            &hostname
                                        ),
                                    ));
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            // DNS resolution failed, try fallback immediately
                            eprintln!(
                                "❌ WASI DNS resolution failed for {}: {:?}, trying fallback",
                                &hostname, e
                            );

                            // Clean up WASI resources before falling back
                            *pollable = None;
                            *waker_bridge = None;

                            if let Some(fallback_addrs) = get_fallback_address(&hostname) {
                                let socket_addrs = fallback_addrs
                                    .into_iter()
                                    .map(|ip| SocketAddr::new(ip, *port))
                                    .collect();
                                self.state = ResolverState::Done(socket_addrs);
                                continue;
                            } else {
                                self.state = ResolverState::Error(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("WASI DNS resolution error: {:?}", e),
                                ));
                                continue;
                            }
                        }
                    }
                }
                ResolverState::Done(ref mut addrs) => {
                    let result = std::mem::take(addrs).into_iter();
                    return Poll::Ready(Ok(result));
                }
                ResolverState::Error(ref mut error) => {
                    let err = std::mem::replace(error, io::Error::new(io::ErrorKind::Other, ""));
                    return Poll::Ready(Err(err));
                }
            }
        }
    }
}

#[cfg(target_os = "wasi")]
fn attempt_wasi_dns_resolution(hostname: &str, port: u16) -> Result<ResolverState, String> {
    // Get the default network instance
    let network = instance_network();

    // Attempt to resolve the hostname using WASI DNS
    match resolve_addresses(&network, hostname) {
        Ok(stream) => Ok(ResolverState::WasiResolving {
            stream,
            port,
            addresses: Vec::new(),
            pollable: None,
            waker_bridge: None,
            poll_count: 0,
        }),
        Err(e) => {
            // Fall back to hardcoded list for known hosts if WASI DNS fails
            match get_fallback_address(hostname) {
                Some(addrs) => {
                    let socket_addrs = addrs
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect();
                    Ok(ResolverState::Done(socket_addrs))
                }
                None => Err(format!(
                    "WASI DNS resolution failed: {:?}, and no fallback available for '{}'",
                    e, hostname
                )),
            }
        }
    }
}

#[cfg(target_os = "wasi")]
fn convert_wasi_ip_to_std(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(ipv4) => {
            // WASI Ipv4Address is (u8, u8, u8, u8), std wants [u8; 4]
            IpAddr::V4(std::net::Ipv4Addr::from([ipv4.0, ipv4.1, ipv4.2, ipv4.3]))
        }
        IpAddress::Ipv6(ipv6) => {
            // WASI Ipv6Address is (u16, u16, u16, u16, u16, u16, u16, u16), std wants [u16; 8]
            IpAddr::V6(std::net::Ipv6Addr::from([
                ipv6.0, ipv6.1, ipv6.2, ipv6.3, ipv6.4, ipv6.5, ipv6.6, ipv6.7,
            ]))
        }
    }
}

#[cfg(target_os = "wasi")]
fn get_fallback_address(hostname: &str) -> Option<Vec<IpAddr>> {
    // Minimal fallback list for when WASI DNS is not available
    match hostname {
        // Google STUN servers (multiple IPs for load balancing)
        "stun.l.google.com" => Some(vec![
            "74.125.250.129".parse().unwrap(),
            "172.217.12.129".parse().unwrap(),
        ]),
        "stun1.l.google.com" => Some(vec!["142.250.191.127".parse().unwrap()]),
        "stun2.l.google.com" => Some(vec!["74.125.250.129".parse().unwrap()]),
        "stun3.l.google.com" => Some(vec!["142.250.191.127".parse().unwrap()]),
        "stun4.l.google.com" => Some(vec!["74.125.250.129".parse().unwrap()]),

        // Cloudflare STUN servers (highly reliable) - IPv4 only to avoid address family issues
        "stun.cloudflare.com" => Some(vec!["162.159.207.0".parse().unwrap()]),

        // Metered STUN servers
        "stun.relay.metered.ca" => Some(vec!["172.105.120.210".parse().unwrap()]),

        // DNS servers for testing - IPv4 only
        "dns.google" => Some(vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()]),
        "one.one.one.one" => Some(vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()]),

        // Common websites for DNS testing (with real current IPs) - IPv4 only
        "google.com" => Some(vec!["142.250.193.142".parse().unwrap()]),
        "github.com" => Some(vec!["20.207.73.82".parse().unwrap()]),
        "cloudflare.com" => Some(vec!["104.16.124.96".parse().unwrap()]),

        // LiveKit Cloud servers - specific instances with real IPs
        "meetings-6ejw8jqa.livekit.cloud" => Some(vec![
            // IPv4 addresses (verified 2025-08-02)
            "138.2.87.159".parse().unwrap(),
            "158.178.239.127".parse().unwrap(),
            // IPv6 addresses for future WASI IPv6 support
            // "2603:c021:4006:3f01:49e1:b97c:efc5:5ad".parse().unwrap(),
            // "2603:c021:4006:3f01:41f9:14f2:a079:697f".parse().unwrap(),
        ]),
        "3ghzjxna20l.sip.livekit.cloud" => Some(vec!["129.151.44.211".parse().unwrap()]),

        // Generic LiveKit Cloud domains - for unknown subdomains, we don't have fallbacks
        // but we can at least provide better error messages
        hostname if hostname.ends_with(".livekit.cloud") => {
            eprintln!(
                "⚠️ LiveKit hostname {} requires real DNS resolution - add specific IP to fallback list if needed",
                hostname
            );
            eprintln!("💡 Known LiveKit IPs: meetings-6ejw8jqa (144.24.122.113, 140.245.14.146), 3ghzjxna20l.sip (129.151.44.211)");
            None
        }

        _ => None,
    }
}
