#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]

extern crate alloc;

#[cfg(not(feature = "std"))]
use linked_list_allocator::LockedHeap;

pub mod types;
pub mod cosem;
pub mod xdlms;
pub mod hdlc;
pub mod client;
pub mod acse;
pub mod server;
pub mod transport;
pub mod cosem_object;
pub mod data;
pub mod register;
pub mod clock;
pub mod hdlc_transport;
pub mod wrapper_transport;
pub mod security;
pub mod association_ln;
pub mod sap_assignment;
pub mod error;
pub mod axdr;
pub mod profile_generic;

pub const MAX_PDU_SIZE: usize = 2048;

#[cfg(not(feature = "std"))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(feature = "std"))]
pub fn init_heap(heap_start: usize, heap_size: usize) {
    unsafe {
        ALLOCATOR.lock().init(heap_start as *mut u8, heap_size);
    }
}

#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
