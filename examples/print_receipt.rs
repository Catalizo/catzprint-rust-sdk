//! Prints a receipt from JSON commands.
//!
//! ```sh
//! CATZPRINT_API_KEY=cz_test_... cargo run --example print_receipt [printer_id]
//! ```
//! Without a printer ID the job is routed to a printer with the `receipt` role.

use catzprint::{Client, Column, Command, CreateJob};

#[tokio::main]
async fn main() -> catzprint::Result<()> {
    let client = Client::from_env()?;
    let mut opts = CreateJob::new().title("Order 1042").reference("1042");
    opts = match std::env::args().nth(1) {
        Some(printer_id) => opts.printer(printer_id),
        None => opts.role("receipt"),
    };
    let item = |name: &str, price: &str| {
        Command::columns(vec![
            Column::new(name).width(0.7),
            Column::new(price).align("right"),
        ])
    };
    let receipt = vec![
        Command::text("Cat Café").align("center").bold().size(2),
        Command::text("12 Whisker Lane").align("center"),
        Command::line(),
        item("Flat white", "3.20"),
        item("Croissant", "2.50"),
        Command::line(),
        Command::columns(vec![
            Column::new("Total").bold(),
            Column::new("5.70").align("right").bold(),
        ]),
        Command::feed(1),
        Command::qr("https://example.com/receipts/1042").align("center"),
        Command::text("Thank you!").align("center"),
        Command::cut(),
    ];
    let job = client.jobs().print_receipt(receipt, opts).await?;
    println!(
        "Created job {} ({}), billed as {}",
        job.id, job.status, job.billed_as
    );
    Ok(())
}
