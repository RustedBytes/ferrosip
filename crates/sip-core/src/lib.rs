//! Core runtime pieces shared by transports, the script engine and modules.
#![forbid(unsafe_code)]
// An ignored Result here is a decision: say why (`#[allow]` + reason).
#![warn(clippy::let_underscore_must_use)]

pub mod blst;
pub mod cfgvars;
pub mod corefns;
pub mod dns;
pub mod error;
pub mod flow;
pub mod json;
pub mod limit;
pub mod log;
pub mod lumps;
pub mod module;
pub mod net;
pub mod panic;
pub mod pv;
pub mod pvcore;
pub mod reply;
pub mod route;
pub mod rpc;
pub mod rr;
pub mod schema;
pub mod shm;
pub mod shutdown;
pub mod sig;
pub mod stats;
pub mod sync;
pub mod time;
pub mod timer;

pub use lumps::Lumps;
pub use module::{Arg, Branch, Ctx, Export, ExportFn, Fixed, Handler, Module, Registry, want_args};
pub use net::{ConnId, Dest, Outbound, Proto, TransportEvent};
pub use pv::{Fmt, PvRef, PvSpec, Val};
pub use pvcore::TxnVars;
pub use route::{AsyncPending, Continuation, RouteHub, RouteNames, RouteRoot, RouteRunner};
pub use rpc::RpcTable;
pub use serde_json;
pub use shm::{ShardedMap, fx_hash};
pub use timer::TimerWheel;
