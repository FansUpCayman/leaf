use std::{ffi::CStr, os::raw::c_char};

use bytes::BytesMut;
use log::*;

use leaf::config;

pub mod ios;

mod logger;
use logger::ConsoleWriter;

// this function is available on iOS 13.0+
// use ios::os_proc_available_memory;

#[no_mangle]
pub extern "C" fn run_leaf(path: *const c_char) {

    let loglevel = log::LevelFilter::Trace;
    let mut logger = leaf::common::log::setup_logger(loglevel);
    let console_output = fern::Output::writer(Box::new(ConsoleWriter(BytesMut::new())), "\n");
    logger = logger.chain(console_output);
    
    leaf::common::log::apply_logger(logger);
    
    if let Ok(path) = unsafe { CStr::from_ptr(path).to_str() } {
        let config = leaf::config::from_file(path).expect("read config failed");

        let mut rt = tokio::runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()
            .unwrap();

        let runners = match leaf::util::create_runners(config) {
            Ok(v) => v,
            Err(e) => {
                error!("create runners fialed: {}", e);
                return;
            }
        };

        // let monit_mem = Box::pin(async {
        //     loop {
        //         let n = unsafe { os_proc_available_memory() };
        //         debug!("{} bytes memory available", n);
        //         tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
        //     }
        // });

        rt.block_on(async move {
            tokio::select! {
                _ = futures::future::join_all(runners) => (),
                // _ = monit_mem  => (),
            }
        });
    } else {
        error!("invalid config path");
        return;
    }
}
