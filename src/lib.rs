//! # CatzPrint for Rust
//!
//! The official Rust SDK for the [CatzPrint](https://catzprint.com) cloud
//! printing API: send receipts, PDFs, images and templates to printers
//! attached to CatzPrint stations, follow jobs, and verify webhooks.
//!
//! ```no_run
//! use catzprint::{Client, Command, CreateJob, WaitOptions};
//!
//! # async fn run() -> catzprint::Result<()> {
//! let client = Client::new("cz_test_...")?; // or Client::from_env()
//! let job = client
//!     .jobs()
//!     .print_receipt(
//!         vec![Command::text("Hello!").align("center").bold(), Command::cut()],
//!         CreateJob::new().role("receipt").reference("order-1042"),
//!     )
//!     .await?;
//! let done = client.jobs().wait_for(&job.id, WaitOptions::default()).await?;
//! println!("{} → {}", done.id, done.status);
//! # Ok(()) }
//! ```
//!
//! ## Features
//! - `sealed` (default): client-side NaCl sealed-box encryption of job content
//!   ([`CreateJob::sealed`]).
//! - `blocking`: a synchronous client in the `blocking` module.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod client;
mod core;
mod error;
mod models;
mod params;
mod seal;
pub mod webhooks;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

pub use crate::client::{Client, JobIter, Jobs, Locations, Printers, Templates};
pub use crate::core::{ClientBuilder, DEFAULT_BASE_URL, USER_AGENT};
pub use crate::error::{ApiError, Error, Result};
pub use crate::models::{
    Job, JobEvent, JobPage, JobStatus, Key, Location, Printer, Template, WebhookEvent,
};
pub use crate::params::{Column, Command, Content, CreateJob, ListJobs, Reprint, WaitOptions};
#[cfg(feature = "sealed")]
#[cfg_attr(docsrs, doc(cfg(feature = "sealed")))]
pub use crate::seal::{seal, seal_base64_key};
