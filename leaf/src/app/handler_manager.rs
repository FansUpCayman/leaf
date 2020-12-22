use std::{
    collections::{hash_map, HashMap},
    convert::From,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
};

use log::*;

#[cfg(feature = "outbound-chain")]
use crate::proxy::chain;
#[cfg(feature = "outbound-failover")]
use crate::proxy::failover;
#[cfg(feature = "outbound-random")]
use crate::proxy::random;
#[cfg(feature = "outbound-tryall")]
use crate::proxy::tryall;

#[cfg(feature = "outbound-direct")]
use crate::proxy::direct;
#[cfg(feature = "outbound-drop")]
use crate::proxy::drop;
#[cfg(feature = "outbound-redirect")]
use crate::proxy::redirect;
#[cfg(feature = "outbound-shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "outbound-socks")]
use crate::proxy::socks;
#[cfg(feature = "outbound-tls")]
use crate::proxy::tls;
#[cfg(feature = "outbound-trojan")]
use crate::proxy::trojan;
#[cfg(feature = "outbound-vless")]
use crate::proxy::vless;
#[cfg(feature = "outbound-vmess")]
use crate::proxy::vmess;
#[cfg(feature = "outbound-ws")]
use crate::proxy::ws;

use crate::{
    common::dns_client::DnsClient,
    config::{self, Outbound, DNS},
    proxy::{self, ProxyHandler, ProxyHandlerType},
};

pub struct HandlerManager {
    handlers: HashMap<String, Arc<dyn ProxyHandler>>,
    default_handler: Option<String>,
}

impl HandlerManager {
    pub fn new(outbounds: &protobuf::RepeatedField<Outbound>, dns: &DNS) -> Self {
        let mut handlers: HashMap<String, Arc<dyn ProxyHandler>> = HashMap::new();
        let mut default_handler: Option<String> = None;
        let mut dns_servers = Vec::new();
        for dns_server in dns.servers.iter() {
            if let Ok(ip) = dns_server.parse::<IpAddr>() {
                dns_servers.push(SocketAddr::new(ip, 53));
            }
        }
        if dns_servers.is_empty() {
            panic!("no dns servers");
        }
        let dns_bind_addr = {
            let addr = format!("{}:0", &dns.bind);
            let addr = match SocketAddrV4::from_str(&addr) {
                Ok(a) => a,
                Err(e) => {
                    error!("invalid bind addr [{}] in dns: {}", &dns.bind, e);
                    panic!("");
                }
            };
            SocketAddr::from(addr)
        };
        let dns_client = Arc::new(DnsClient::new(dns_servers, dns_bind_addr));
        let mut socksTcpHandler: Option<Box<socks::outbound::TcpHandler>> = None;
        let mut trojanUdpHandler: Option<Box<trojan::UdpHandler>> = None;
        let mut tag: Option<String> = None;
        for outbound in outbounds.iter() {
            let outboundTag = String::from(&outbound.tag);
            if default_handler.is_none() {
                default_handler = Some(String::from(&outbound.tag));
                debug!("default handler [{}]", &outbound.tag);
            }
            let bind_addr = {
                let addr = format!("{}:0", &outbound.bind);
                let addr = match SocketAddrV4::from_str(&addr) {
                    Ok(a) => a,
                    Err(e) => {
                        error!(
                            "invalid bind addr [{}] in outbound {}: {}",
                            &outbound.bind, &outbound.tag, e
                        );
                        panic!("");
                    }
                };
                SocketAddr::from(addr)
            };
            match outbound.protocol.as_str() {
                #[cfg(feature = "outbound-socks")]
                "socks" => {
                    tag = Some(outboundTag);
                    let settings = match protobuf::parse_from_bytes::<config::SocksOutboundSettings>(
                        &outbound.settings,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [socks] outbound settings: {}", e);
                            continue;
                        }
                    };
                    let tcp = Box::new(socks::outbound::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    socksTcpHandler = Some(tcp);
                }
                
                #[cfg(feature = "outbound-trojan")]
                "trojan" => {
                    let settings = match protobuf::parse_from_bytes::<config::TrojanOutboundSettings>(
                        &outbound.settings,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid trojan outbound settings: {}", e);
                            continue;
                        }
                    };
                    let udp = Box::new(trojan::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        password: settings.password,
                        // domain: settings.domain,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    trojanUdpHandler = Some(udp);
                }
                "tryall" | "failover" | "random" | "chain" => (),
                _ => {
                    warn!("unknown outbound protocol {:?}", outbound.protocol);
                }
            }
        }
        let sockstag = tag.unwrap();
        let handler = proxy::Handler::new(
            sockstag.clone(),
            colored::Color::Cyan,
            ProxyHandlerType::Endpoint,
            socksTcpHandler.unwrap(),
            trojanUdpHandler.unwrap(),
        );
        handlers.insert(sockstag, handler);
        // FIXME a better way to find outbound deps?
        for _i in 0..4 {
            for outbound in outbounds.iter() {
                let tag = String::from(&outbound.tag);
                match outbound.protocol.as_str() {
                    #[cfg(feature = "outbound-tryall")]
                    "tryall" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::TryAllOutboundSettings,
                        >(&outbound.settings)
                        {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(tryall::TcpHandler {
                            actors: actors.clone(),
                            delay_base: settings.delay_base,
                        });
                        let udp = Box::new(tryall::UdpHandler {
                            actors,
                            delay_base: settings.delay_base,
                        });
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-random")]
                    "random" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::RandomOutboundSettings,
                        >(&outbound.settings)
                        {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(random::TcpHandler {
                            actors: actors.clone(),
                        });
                        let udp = Box::new(random::UdpHandler { actors });
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-failover")]
                    "failover" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::FailOverOutboundSettings,
                        >(&outbound.settings)
                        {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(failover::TcpHandler::new(
                            actors.clone(),
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                        ));
                        let udp = Box::new(failover::UdpHandler::new(
                            actors,
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                        ));
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-chain")]
                    "chain" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::ChainOutboundSettings,
                        >(&outbound.settings)
                        {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(chain::TcpHandler {
                            actors: actors.clone(),
                            dns_client: dns_client.clone(),
                        });
                        let udp = Box::new(chain::UdpHandler {
                            actors: actors.clone(),
                            dns_client: dns_client.clone(),
                        });
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 226,
                                g: 103,
                                b: 245,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    "direct" | "drop" | "redirect" | "socks" | "shadowsocks" | "trojan"
                    | "vmess" | "vless" | "tls" | "ws" | "h2" => (),
                    _ => {
                        warn!("unknown outbound protocol {:?}", outbound.protocol);
                    }
                }
            }
        }

        HandlerManager {
            handlers,
            default_handler,
        }
    }

    pub fn add(&mut self, tag: String, handler: Arc<dyn ProxyHandler>) {
        self.handlers.insert(tag, handler);
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<dyn ProxyHandler>> {
        self.handlers.get(tag)
    }

    pub fn default_handler(&self) -> Option<&String> {
        self.default_handler.as_ref()
    }

    pub fn handlers(&self) -> Handlers {
        Handlers {
            inner: self.handlers.values(),
        }
    }
}

pub struct Handlers<'a> {
    inner: hash_map::Values<'a, String, Arc<dyn ProxyHandler>>,
}

impl<'a> Iterator for Handlers<'a> {
    type Item = &'a Arc<dyn ProxyHandler>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
