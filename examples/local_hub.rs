//! A CatzServe-style kitchen hub that keeps printing when the internet is
//! down: stations on the LAN first, the cloud only when no station answers.
//!
//! ```sh
//! CATZPRINT_API_KEY=cz_live_... cargo run --example local_hub -- <location_id> [template_id]
//! ```

use catzprint::{
    Client, Column, Command, CreateJob, Error, FileTokenStore, LocalConfig, LocalMode,
};
use serde_json::json;

#[tokio::main]
async fn main() -> catzprint::Result<()> {
    let mut args = std::env::args().skip(1);
    let location_id = args
        .next()
        .expect("usage: local_hub <location_id> [template_id]");
    let template_id = args.next();
    let order_id = 1042;

    let client = Client::builder() // the API key comes from CATZPRINT_API_KEY
        .local(
            LocalConfig::new(LocalMode::LocalFirst)
                .location_id(&location_id)
                .discover(true) // the cloud's endpoint list + mDNS on the LAN
                .token_store(FileTokenStore::new("catzprint-local.json"))
                .device_name("CatzServe hub"),
        )
        .build()?;

    // A kitchen ticket: an inverted ALLERGY banner, then the order. One key
    // per ticket and attempt: the station and the cloud both dedupe on it,
    // so a fallback or a retry never prints twice.
    let ticket = vec![
        Command::text(" ALLERGY: PEANUTS ")
            .align("center")
            .bold()
            .invert()
            .size(2),
        Command::text("Table 12").bold().size(2),
        Command::line(),
        Command::columns(vec![
            Column::new("2 x").width(0.15),
            Column::new("Pad thai").bold(),
        ]),
        Command::text("   no egg"),
        Command::cut(),
    ];
    let result = client
        .jobs()
        .print_receipt(
            ticket,
            CreateJob::new()
                .role("kitchen")
                .reference(format!("order-{order_id}"))
                .idempotency_key(format!("order-{order_id}-kitchen-r1")),
        )
        .await;
    match result {
        Ok(job) => println!(
            "{} {} via {:?} (live: {})",
            job.id, job.status, job.via, job.live
        ),
        Err(e) if e.is_printer_offline() || e.is_out_of_paper() || e.is_cover_open() => {
            eprintln!("Tell the kitchen: {e}. Send it again later with the same key.");
        }
        Err(e @ Error::StationUnreachable { .. }) => {
            for a in e.station_attempts() {
                eprintln!("tried {}: {}", a.url, a.error);
            }
            eprintln!("cloud: {:?}", e.cloud_error().map(|c| c.to_string()));
        }
        Err(e) => eprintln!("{e}"),
    }

    // Or a saved template with data (templates are synced to the station).
    if let Some(tpl) = template_id {
        let job = client
            .jobs()
            .print_template(
                tpl,
                json!({"table": "12", "allergy": "PEANUTS",
                    "items": [{"qty": 2, "name": "Pad thai", "note": "no egg"}]}),
                CreateJob::new()
                    .role("kitchen")
                    .idempotency_key(format!("order-{order_id}-kitchen-r1")),
            )
            .await?;
        println!("{} {} via {:?}", job.id, job.status, job.via);
    }

    let status = client.local().status().await?;
    println!(
        "station {}: {} unsynced, {} offline prints left",
        status.station.name, status.unsynced, status.allowance.prints_left
    );
    client.close().await;
    Ok(())
}
