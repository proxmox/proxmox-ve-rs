use std::fmt::{self, Write};

use crate::{
    openfabric::{OpenfabricInterface, OpenfabricRouter},
    ospf::{OspfInterface, OspfRouter},
    route_map::{AccessList, AccessListName, ProtocolRouteMap, RouteMap},
    FrrConfig, Interface, InterfaceName, Router, RouterName,
};

pub struct FrrConfigBlob<'a> {
    buf: &'a mut (dyn Write + 'a),
}

impl Write for FrrConfigBlob<'_> {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.buf.write_str(s)
    }
}

pub trait FrrSerializer {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result;
}

pub fn to_raw_config(frr_config: &FrrConfig) -> Result<Vec<String>, anyhow::Error> {
    let mut out = String::new();
    let mut blob = FrrConfigBlob { buf: &mut out };
    frr_config.serialize(&mut blob)?;

    Ok(out.as_str().lines().map(String::from).collect())
}

pub fn dump(config: &FrrConfig) -> Result<String, anyhow::Error> {
    let mut out = String::new();
    let mut blob = FrrConfigBlob { buf: &mut out };
    config.serialize(&mut blob)?;
    Ok(out)
}

impl FrrSerializer for FrrConfig {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        self.router().try_for_each(|router| router.serialize(f))?;
        self.interfaces()
            .try_for_each(|interface| interface.serialize(f))?;
        self.access_lists().try_for_each(|list| list.serialize(f))?;
        self.routemaps().try_for_each(|map| map.serialize(f))?;
        self.protocol_routemaps()
            .try_for_each(|pm| pm.serialize(f))?;
        Ok(())
    }
}

impl FrrSerializer for (&RouterName, &Router) {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        let router_name = self.0;
        let router = self.1;
        writeln!(f, "router {router_name}")?;
        router.serialize(f)?;
        writeln!(f, "exit")?;
        writeln!(f, "!")?;
        Ok(())
    }
}

impl FrrSerializer for (&InterfaceName, &Interface) {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        let interface_name = self.0;
        let interface = self.1;
        writeln!(f, "interface {interface_name}")?;
        interface.serialize(f)?;
        writeln!(f, "exit")?;
        writeln!(f, "!")?;
        Ok(())
    }
}

impl FrrSerializer for (&AccessListName, &AccessList) {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        self.1.serialize(f)?;
        writeln!(f, "!")
    }
}

impl FrrSerializer for Interface {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        match self {
            Interface::Openfabric(openfabric_interface) => openfabric_interface.serialize(f)?,
            Interface::Ospf(ospf_interface) => ospf_interface.serialize(f)?,
        }
        Ok(())
    }
}

impl FrrSerializer for OpenfabricInterface {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        if self.is_ipv6 {
            writeln!(f, " ipv6 router {}", self.fabric_id)?;
        }
        if self.is_ipv4 {
            writeln!(f, " ip router {}", self.fabric_id)?;
        }
        if self.passive == Some(true) {
            writeln!(f, " openfabric passive")?;
        }
        if let Some(interval) = self.hello_interval {
            writeln!(f, " openfabric hello-interval {interval}",)?;
        }
        if let Some(multiplier) = self.hello_multiplier {
            writeln!(f, " openfabric hello-multiplier {multiplier}",)?;
        }
        if let Some(interval) = self.csnp_interval {
            writeln!(f, " openfabric csnp-interval {interval}",)?;
        }
        Ok(())
    }
}

impl FrrSerializer for OspfInterface {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        writeln!(f, " ip ospf {}", self.area)?;
        if self.passive == Some(true) {
            writeln!(f, " ip ospf passive")?;
        }
        if let Some(network_type) = &self.network_type {
            writeln!(f, " ip ospf network {network_type}")?;
        }
        Ok(())
    }
}

impl FrrSerializer for Router {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        match self {
            Router::Openfabric(open_fabric_router) => open_fabric_router.serialize(f),
            Router::Ospf(ospf_router) => ospf_router.serialize(f),
        }
    }
}

impl FrrSerializer for OpenfabricRouter {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        writeln!(f, " net {}", self.net())?;
        Ok(())
    }
}

impl FrrSerializer for OspfRouter {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        writeln!(f, " ospf router-id {}", self.router_id())?;
        Ok(())
    }
}

impl FrrSerializer for AccessList {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        for i in &self.rules {
            if i.network.is_ipv6() {
                write!(f, "ipv6 ")?;
            }
            write!(f, "access-list {} ", self.name)?;
            if let Some(seq) = i.seq {
                write!(f, "seq {seq} ")?;
            }
            write!(f, "{} ", i.action)?;
            writeln!(f, "{}", i.network)?;
        }
        writeln!(f, "!")?;
        Ok(())
    }
}

impl FrrSerializer for RouteMap {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        writeln!(f, "route-map {} {} {}", self.name, self.action, self.seq)?;
        for i in &self.matches {
            writeln!(f, " {}", i)?;
        }
        for i in &self.sets {
            writeln!(f, " {}", i)?;
        }
        writeln!(f, "exit")?;
        writeln!(f, "!")
    }
}

impl FrrSerializer for ProtocolRouteMap {
    fn serialize(&self, f: &mut FrrConfigBlob<'_>) -> fmt::Result {
        if self.is_ipv6 {
            writeln!(
                f,
                "ipv6 protocol {} route-map {}",
                self.protocol, self.routemap_name
            )?;
        } else {
            writeln!(
                f,
                "ip protocol {} route-map {}",
                self.protocol, self.routemap_name
            )?;
        }
        writeln!(f, "!")?;
        Ok(())
    }
}
