use ic_replicated_state::{PageIndex, PageMap};
use memory_tracker::SigsegvMemoryTracker;
use std::convert::TryFrom;

/// Helper function to create a memory tracking SIGSEGV handler function.
pub fn sigsegv_memory_tracker_handler<'a, T: 'a>(
    sigsegv_memory_tracker: std::rc::Rc<SigsegvMemoryTracker>,
    // if supplied, faulted pages will be initialized from the PageMap
    page_map: std::rc::Rc<Option<PageMap>>,
    current_heap_size: impl Fn() -> usize + 'a,
    default_handler: impl Fn() -> T + 'a,
    handler_succeeded: impl Fn() -> T + 'a,
    handler_failed: impl Fn() -> T + 'a,
) -> impl Fn(i32, *const libc::siginfo_t, *const libc::c_void) -> T + 'a {
    move |signum: i32, siginfo_ptr: *const libc::siginfo_t, _ucontext_ptr| {
        use nix::sys::signal::Signal;

        let signal = Signal::try_from(signum).expect("signum is a valid signal");
        let (_si_signo, _si_errno, _si_code, si_addr) = unsafe {
            let s = *siginfo_ptr;
            (s.si_signo, s.si_errno, s.si_code, s.si_addr())
        };
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> instance signal handler: signal = {}, si_signo = {}, si_errno = {}, si_code = {}, si_addr = {:?}",
            signal, _si_signo, _si_errno, _si_code, si_addr
        );

        let check_if_expanded = || unsafe {
            let heap_size = current_heap_size();
            let heap_start = sigsegv_memory_tracker.area().addr() as *mut libc::c_void;
            if (heap_start <= si_addr) && (si_addr < { heap_start.add(heap_size) }) {
                Some(heap_size)
            } else {
                None
            }
        };

        let expected_signal =
            // Mac OS raises SIGBUS instead of SIGSEGV
            if cfg!(target_os = "macos") {
                Signal::SIGBUS
            } else {
                Signal::SIGSEGV
            };

        if signal != expected_signal {
            return default_handler();
        }
        // We handle SIGSEGV from the Wasm module heap ourselves.
        if sigsegv_memory_tracker.area().is_within(si_addr) {
            #[cfg(feature = "sigsegv_handler_debug")]
            eprintln!("> instance signal handler: calling memory tracker signal handler");
            // Returns true if the signal has been handled by our handler which indicates
            // that the instance should continue.
            //
            // If a PageMap is given, the page contents are initialized from the PageMap. If
            // no PageMap is given, the page contents are not initialized (when
            // used with mmap-ed file the page contents will come from the file)
            let handled = if let Some(page_map) = page_map.as_ref() {
                sigsegv_memory_tracker.handle_sigsegv(
                    |n| Some(page_map.get_page(PageIndex::from(n as u64))),
                    si_addr,
                )
            } else {
                sigsegv_memory_tracker.handle_sigsegv(|_| None, si_addr)
            };
            if handled {
                handler_succeeded()
            } else {
                handler_failed()
            }
        // The heap has expanded. Update tracked memory area.
        } else if let Some(heap_size) = check_if_expanded() {
            let delta = heap_size - sigsegv_memory_tracker.area().size();
            #[cfg(feature = "sigsegv_handler_debug")]
            eprintln!(
                "> instance signal handler: expanding memory area by {}",
                delta
            );
            sigsegv_memory_tracker.expand(delta);
            handler_succeeded()
        } else {
            default_handler()
        }
    }
}
