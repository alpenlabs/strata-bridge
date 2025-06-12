//! A tiny crate that runs a HTTP server and exposes jemalloc's heap allocation profile data. Not
//! compatible with Windows/MSVC.

use std::net::{IpAddr, Ipv4Addr};

use tracing::info;

/// Main setup function. Must be called inside a tokio runtime with jemalloc set as the global
/// allocator with the cargo features `profiling` and `unprefixed_malloc_on_supported_platforms`. It
/// also need to be configured as such:
///
/// ```rs
/// #[allow(non_upper_case_globals)]
/// #[export_name = "malloc_conf"]
/// pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";
/// ```
pub fn setup_memory_profiling(port: u16) {
    tokio::spawn(async move {
        info!("memory profiling active on TCP HTTP port {port}");
        use axum::{http::StatusCode, response::IntoResponse};

        async fn handle_get_heap() -> Result<impl IntoResponse, (StatusCode, String)> {
            let mut prof_ctl = jemalloc_pprof::PROF_CTL.as_ref().unwrap().lock().await;
            require_profiling_activated(&prof_ctl)?;
            let pprof = prof_ctl
                .dump_pprof()
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            Ok(pprof)
        }

        async fn handle_get_heap_flamegraph() -> Result<impl IntoResponse, (StatusCode, String)> {
            use axum::{body::Body, http::header::CONTENT_TYPE, response::Response};

            let mut prof_ctl = jemalloc_pprof::PROF_CTL.as_ref().unwrap().lock().await;
            require_profiling_activated(&prof_ctl)?;
            let svg = prof_ctl
                .dump_flamegraph()
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            Response::builder()
                .header(CONTENT_TYPE, "image/svg+xml")
                .body(Body::from(svg))
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
        }

        /// Checks whether jemalloc profiling is activated an returns an error response
        /// if not.
        fn require_profiling_activated(
            prof_ctl: &jemalloc_pprof::JemallocProfCtl,
        ) -> Result<(), (StatusCode, String)> {
            if prof_ctl.activated() {
                Ok(())
            } else {
                Err((
                    axum::http::StatusCode::FORBIDDEN,
                    "heap profiling not activated".into(),
                ))
            }
        }

        let app = axum::Router::new()
            .route("/debug/pprof/heap", axum::routing::get(handle_get_heap))
            .route(
                "/debug/pprof/heap/flamegraph",
                axum::routing::get(handle_get_heap_flamegraph),
            );

        // run our app with hyper, listening globally on port
        let listener = tokio::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
            .await
            .unwrap();
        axum::serve(listener, app).await.unwrap();
    });
}
