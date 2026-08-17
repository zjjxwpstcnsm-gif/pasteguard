mod dashboard;
mod editor;

use std::{fs, sync::Arc};

use anyhow::Result;
use directories::ProjectDirs;
use gpui::{AppContext, Application, WindowBounds, WindowOptions, px, size};
use gpui_component::Root;
use punctual_engine::{EngineConfig, EngineHandle};
use punctual_storage::SqliteTaskRepository;

use crate::dashboard::PunctualDashboard;

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let project_dirs = ProjectDirs::from("dev", "punctual", "Punctual")
        .expect("the operating system must expose a user data directory");
    fs::create_dir_all(project_dirs.data_dir())?;
    let database_path = project_dirs.data_dir().join("punctual.db");
    let repository = Arc::new(SqliteTaskRepository::open(database_path)?);

    let engine = EngineHandle::start(
        Arc::clone(&repository),
        EngineConfig {
            profile_dir: project_dirs.data_dir().join("browser-profile"),
            ..EngineConfig::default()
        },
    )?;

    let app = Application::new();
    app.run(move |cx| {
        gpui_component::init(cx);

        let window_options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(
                size(px(1280.0), px(820.0)),
                cx,
            )),
            ..Default::default()
        };

        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        cx.open_window(window_options, move |window, cx| {
            let view = cx.new(|cx| {
                PunctualDashboard::new(repository, engine, window, cx)
            });
            cx.new(|cx| Root::new(view, window, cx))
        })
        .expect("failed to open the Punctual window");
    });
    Ok(())
}
