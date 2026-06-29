// src/main.rs — gmacFTP entry point. The Slint UI module + the app controller.
slint::include_modules!();

mod app;
mod macos_menu;

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    tracing::info!(target: "gmacftp", "starting");
    app::run();
}
