//! Prints a PDF, sealed on this machine, and waits until it has printed.
//!
//! ```sh
//! CATZPRINT_API_KEY=cz_live_... cargo run --example print_pdf_and_wait -- invoice.pdf <printer_id>
//! ```

use std::time::Duration;

use catzprint::{Client, CreateJob, Error, WaitOptions};

#[tokio::main]
async fn main() -> catzprint::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(printer_id)) = (args.next(), args.next()) else {
        eprintln!("usage: print_pdf_and_wait <file.pdf> <printer_id>");
        std::process::exit(2);
    };
    let client = Client::from_env()?;
    let job = client
        .jobs()
        .print_pdf_file(&path, CreateJob::new().printer(printer_id).sealed(true))
        .await?;
    println!("Sent {path} as job {}; waiting…", job.id);
    let wait = WaitOptions {
        timeout: Duration::from_secs(120),
        interval: Duration::from_secs(2),
    };
    match client.jobs().wait_for(&job.id, wait).await {
        Ok(done) => println!(
            "Job {} finished: {} {}",
            done.id, done.status, done.status_detail
        ),
        Err(Error::WaitTimeout { last_status, .. }) => {
            println!("Still {last_status} after two minutes. Is the station online?")
        }
        Err(e) => return Err(e),
    }
    Ok(())
}
