// Load the allocator
cfg_if::cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        use wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc<'_> = wee_alloc::WeeAlloc::INIT;
    }
}

pub mod futures;
pub use self::futures::kickstart;
use self::futures::{CallFuture, FutureResult, RefCounted};
use ic_base_types::PrincipalId;
use on_wire::{FromWire, IntoWire, NewType};
use std::convert::TryFrom;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{cell::RefCell, future::Future};

/// This is a simplified version of `ic_types::Funds`.
pub struct Funds {
    pub cycles: u64,
    pub icpts: u64,
}

impl Funds {
    pub fn new(cycles: u64, icpts: u64) -> Self {
        Self { cycles, icpts }
    }

    pub fn zero() -> Self {
        Self {
            cycles: 0,
            icpts: 0,
        }
    }
}

pub type CanisterId = ic_base_types::CanisterId;

/// This is the raw system API as documented by the dfinity public spec
/// I would advise not using this as it's difficult to use and likely to change
#[allow(dead_code)]
#[cfg(target_arch = "wasm32")]
pub mod ic0 {
    #[link(wasm_import_module = "ic0")]
    extern "C" {
        pub fn canister_self_copy(dst: u32, offset: u32, size: u32);
        pub fn canister_self_size() -> u32;
        pub fn controller_copy(dst: u32, offset: u32, size: u32);
        pub fn controller_size() -> u32;
        pub fn debug_print(offset: u32, size: u32);
        pub fn msg_arg_data_copy(dst: u32, offset: u32, size: u32);
        pub fn msg_arg_data_size() -> u32;
        pub fn msg_caller_copy(dst: u32, offset: u32, size: u32);
        pub fn msg_caller_size() -> u32;
        pub fn msg_reject(src: u32, size: u32);
        pub fn msg_reject_code() -> i32;
        pub fn msg_reject_msg_copy(dst: u32, offset: u32, size: u32);
        pub fn msg_reject_msg_size() -> u32;
        pub fn msg_reply();
        pub fn msg_funds_accept(unit_src: u32, unit_size: u32, amount: u64) -> ();
        pub fn msg_reply_data_append(offset: u32, size: u32);
        pub fn trap(offset: u32, size: u32);
        pub fn call_simple(
            callee_src: u32,
            callee_size: u32,
            name_src: u32,
            name_size: u32,
            reply_fun: usize,
            reply_env: u32,
            reject_fun: usize,
            reject_env: u32,
            data_src: u32,
            data_size: u32,
        ) -> i32;
        pub fn call_new(
            callee_src: u32,
            callee_size: u32,
            name_src: u32,
            name_size: u32,
            reply_fun: usize,
            reply_env: u32,
            reject_fun: usize,
            reject_env: u32,
        );
        pub fn call_data_append(src: u32, size: u32);
        pub fn call_funds_add(unit_src: u32, unit_size: u32, amount: u64);
        pub fn call_perform() -> i32;
        pub fn stable_size() -> u32;
        pub fn stable_grow(additional_pages: u32) -> i32;
        pub fn stable_read(dst: u32, offset: u32, size: u32);
        pub fn stable_write(offset: u32, src: u32, size: u32);
        pub fn time() -> u64;
        pub fn canister_balance(unit_src: u32, unit_size: u32) -> u64;
        pub fn msg_funds_available(unit_src: u32, unit_size: u32) -> u64;
        pub fn msg_funds_refunded(unit_src: u32, unit_size: u32) -> u64;
        pub fn certified_data_set(src: u32, size: u32);
        pub fn data_certificate_present() -> u32;
        pub fn data_certificate_size() -> u32;
        pub fn data_certificate_copy(dst: u32, offset: u32, size: u32);
    }
}

/*
These stubs exist for when you're compiling this code not on a canister. If you
delete this, the code will still build fine on OS X, but will fail to link on
Linux.

We want to allow this code to be compiled on x86, albeit not run, to allow for
sharing of types between WASM and x86 programs in crates which depend on this.
*/
#[allow(clippy::too_many_arguments)]
#[allow(clippy::missing_safety_doc)]
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub mod ic0 {
    fn wrong_arch<A>(s: &str) -> A {
        panic!("{} should only be called inside canisters", s)
    }

    pub unsafe fn canister_self_copy(_dst: u32, _offset: u32, _size: u32) {
        wrong_arch("canister_self_copy")
    }
    pub unsafe fn canister_self_size() -> u32 {
        wrong_arch("canister_self_size")
    }
    pub unsafe fn controller_copy(_dst: u32, _offset: u32, _size: u32) {
        wrong_arch("controller_copy")
    }
    pub unsafe fn controller_size() -> u32 {
        wrong_arch("controller_size")
    }
    pub unsafe fn debug_print(_offset: u32, _size: u32) {
        wrong_arch("debug_print")
    }
    pub unsafe fn msg_arg_data_copy(_dst: u32, _offset: u32, _size: u32) {
        wrong_arch("msg_arg_data_copy")
    }
    pub unsafe fn msg_arg_data_size() -> u32 {
        wrong_arch("msg_arg_data_size")
    }
    pub unsafe fn msg_caller_copy(_dst: u32, _offset: u32, _size: u32) {
        wrong_arch("msg_caller_copy")
    }
    pub unsafe fn msg_caller_size() -> u32 {
        wrong_arch("msg_caller_size")
    }
    pub unsafe fn msg_reject(_src: u32, _size: u32) {
        wrong_arch("msg_reject")
    }
    pub unsafe fn msg_reject_code() -> i32 {
        wrong_arch("msg_reject_code")
    }
    pub unsafe fn msg_reject_msg_copy(_dst: u32, _offset: u32, _size: u32) {
        wrong_arch("msg_reject_msg_copy")
    }
    pub unsafe fn msg_reject_msg_size() -> u32 {
        wrong_arch("msg_reject_msg_size")
    }
    pub unsafe fn msg_reply() {
        wrong_arch("msg_reply")
    }
    pub unsafe fn msg_reply_data_append(_offset: u32, _size: u32) {
        wrong_arch("msg_reply_data_append")
    }
    pub unsafe fn msg_funds_accept(_unit_src: u32, _unit_size: u32, _amount: u64) {
        wrong_arch("msg_funds_accept")
    }
    pub unsafe fn trap(_offset: u32, _size: u32) {
        wrong_arch("trap")
    }
    pub unsafe fn call_simple(
        _callee_src: u32,
        _callee_size: u32,
        _name_src: u32,
        _name_size: u32,
        _reply_fun: usize,
        _reply_env: u32,
        _reject_fun: usize,
        _reject_env: u32,
        _data_src: u32,
        _data_size: u32,
    ) -> i32 {
        wrong_arch("call_simple")
    }

    pub unsafe fn call_new(
        _callee_src: u32,
        _callee_size: u32,
        _name_src: u32,
        _name_size: u32,
        _reply_fun: usize,
        _reply_env: u32,
        _reject_fun: usize,
        _reject_env: u32,
    ) {
        wrong_arch("call_new")
    }

    pub unsafe fn call_data_append(_src: u32, _size: u32) {
        wrong_arch("call_data_append")
    }

    pub unsafe fn call_funds_add(_unit_src: u32, _unit_size: u32, _amount: u64) {
        wrong_arch("call_funds_add")
    }

    pub unsafe fn call_perform() -> i32 {
        wrong_arch("call_perform")
    }

    pub unsafe fn stable_size() -> u32 {
        wrong_arch("stable_size")
    }

    pub unsafe fn stable_grow(_additional_pages: u32) -> i32 {
        wrong_arch("stable_grow")
    }

    pub unsafe fn stable_read(_dst: u32, _offset: u32, _size: u32) {
        wrong_arch("stable_read")
    }

    pub unsafe fn stable_write(_offset: u32, _src: u32, _size: u32) {
        wrong_arch("stable_write")
    }

    pub unsafe fn time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    pub unsafe fn canister_balance(_unit_src: u32, _unit_size: u32) -> u64 {
        wrong_arch("canister_balance")
    }

    pub unsafe fn msg_funds_available(_unit_src: u32, _unit_size: u32) -> u64 {
        wrong_arch("msg_funds_available")
    }

    pub unsafe fn msg_funds_refunded(_unit_src: u32, _unit_size: u32) -> u64 {
        wrong_arch("msg_funds_refunded")
    }
    pub unsafe fn certified_data_set(_src: u32, _size: u32) {
        wrong_arch("certified_data_set")
    }

    pub unsafe fn data_certificate_present() -> u32 {
        wrong_arch("data_certificate_present")
    }

    pub unsafe fn data_certificate_size() -> u32 {
        wrong_arch("data_certificate_size")
    }

    pub unsafe fn data_certificate_copy(_dst: u32, _offset: u32, _size: u32) {
        wrong_arch("data_certificate_copy")
    }
}

// Convenience wrappers around the DFINTY System API

/// A thin wrapper around `call_simple`.  Calls another canisters and invokes
/// on_reply/on_reject with the given `env` once reply/reject is received.
#[allow(clippy::too_many_arguments)]
pub fn call_raw(
    id: CanisterId,
    method: &str,
    data: &[u8],
    on_reply: fn(ptr: *mut ()),
    on_reject: fn(ptr: *mut ()),
    env: *mut (),
    funds: Funds,
) -> i32 {
    unsafe {
        ic0::call_new(
            id.get().as_slice().as_ptr() as u32,
            id.get().as_slice().len() as u32,
            method.as_ptr() as u32,
            method.len() as u32,
            on_reply as usize,
            env as u32,
            on_reject as usize,
            env as u32,
        );
        ic0::call_data_append(data.as_ptr() as u32, data.len() as u32);
        if funds.cycles > 0 {
            call_funds_add(TokenUnit::Cycles, funds.cycles);
        }
        if funds.icpts > 0 {
            call_funds_add(TokenUnit::ICP, funds.icpts);
        }
        ic0::call_perform()
    }
}

/// Calls another canister and executes one of the callbacks.
pub fn call_with_callbacks(
    id: CanisterId,
    method: &str,
    data: &[u8],
    reply: impl FnOnce() + 'static,
    reject: impl FnOnce() + 'static,
) -> i32 {
    type Closures = (Box<dyn FnOnce() + 'static>, Box<dyn FnOnce() + 'static>);
    fn on_reply(env: *mut ()) {
        let closure = unsafe { Box::from_raw(env as *mut Closures) }.0;
        closure();
    }
    fn on_reject(env: *mut ()) {
        let closure = unsafe { Box::from_raw(env as *mut Closures) }.1;
        closure();
    }
    let boxed_closures: Box<Closures> = Box::new((Box::new(reply), Box::new(reject)));
    let env = Box::into_raw(boxed_closures);

    let err_code = call_raw(
        id,
        method,
        data,
        on_reply,
        on_reject,
        env as *mut (),
        Funds::zero(),
    );

    if err_code != 0 {
        // deallocate the closures
        let _ = unsafe { Box::from_raw(env as *mut Closures) };
    }

    err_code
}

/// Calls another canister and returns a future.
pub fn call_bytes(
    id: CanisterId,
    method: &str,
    data: &[u8],
    funds: Funds,
) -> impl Future<Output = futures::FutureResult<Vec<u8>>> {
    // the callback from IC dereferences the future from a raw pointer, assigns the
    // result and calls the waker
    fn callback(future_ptr: *mut ()) {
        let waker = {
            let ref_counted =
                unsafe { RefCounted::from_raw(future_ptr as *const RefCell<CallFuture>) };
            let mut future = ref_counted.borrow_mut();
            future.result = Some(match reject_code() {
                0 => Ok(arg_data()),
                n => Err((Some(n), reject_message())),
            });
            future.waker.clone()
        };
        waker.expect("there is a waker").wake();
    };
    let future_for_closure = RefCounted::new(CallFuture::new());
    let future = future_for_closure.clone();
    let future_ptr = future_for_closure.into_raw();
    let err_code = call_raw(
        id,
        method,
        data,
        callback,
        callback,
        future_ptr as *mut (),
        funds,
    );
    // 0 is a special error code, meaning call_simple call succeeded
    if err_code != 0 {
        // Decrease the refcount as the closure will not be called.
        unsafe { RefCounted::from_raw(future_ptr) };
        future.borrow_mut().result =
            Some(Err((Some(err_code), "Couldn't send message".to_string())));
    }
    future
}

pub async fn call<Payload, ReturnType, Witness>(
    id: CanisterId,
    method: &str,
    _: Witness,
    payload: Payload::Inner,
) -> FutureResult<ReturnType::Inner>
where
    Payload: IntoWire + NewType,
    ReturnType: FromWire + NewType,
    Witness: FnOnce(ReturnType, Payload::Inner) -> (ReturnType::Inner, Payload),
{
    let payload = Payload::from_inner(payload);
    let res: ReturnType = call_explicit(id, method, payload, Funds::zero()).await?;
    Ok(res.into_inner())
}

pub fn call_no_reply<Payload, ReturnType, Witness>(
    id: CanisterId,
    method: &str,
    _: Witness,
    payload: Payload::Inner,
    funds: Funds,
) -> Result<(), String>
where
    Payload: IntoWire + NewType,
    ReturnType: FromWire + NewType,
    Witness: FnOnce(ReturnType, Payload::Inner) -> (ReturnType::Inner, Payload),
{
    // This is a function that does nothing and allocates nothing to the heap
    fn no_op(_: *mut ()) {}
    let payload = Payload::from_inner(payload);
    let bytes: Vec<u8> = payload.into_bytes()?;
    match call_raw(
        id,
        method,
        &bytes,
        no_op,
        no_op,
        std::ptr::null_mut(),
        funds,
    ) {
        0 => Ok(()),
        err_code =>
            Err(format!("ic0.call_perform returned the error code '{}' indicating the call could not be made, when calling {} on canister {:?}",
                        err_code,
                        method,
                        id)),
    }
}

pub async fn call_explicit<Payload, ReturnType>(
    id: CanisterId,
    method: &str,
    payload: Payload,
    funds: Funds,
) -> FutureResult<ReturnType>
where
    Payload: IntoWire + NewType,
    ReturnType: FromWire + NewType,
{
    let bytes: Vec<u8> = payload.into_bytes().map_err(|e| (None, e))?;
    let res: Vec<u8> = call_bytes(id, method, &bytes, funds).await.unwrap();
    ReturnType::from_bytes(res).map_err(|e| (None, e))
}

pub async fn call_with_funds<Payload, ReturnType, Witness>(
    id: CanisterId,
    method: &str,
    _: Witness,
    payload: Payload::Inner,
    funds: Funds,
) -> FutureResult<ReturnType::Inner>
where
    Payload: IntoWire + NewType,
    ReturnType: FromWire + NewType,
    Witness: FnOnce(ReturnType, Payload::Inner) -> (ReturnType::Inner, Payload),
{
    let payload = Payload::from_inner(payload);
    let res: ReturnType = call_explicit(id, method, payload, funds).await?;
    Ok(res.into_inner())
}

pub fn call_funds_add(unit: TokenUnit, amount: u64) {
    let unit_blob: Vec<u8> = unit.into();
    unsafe {
        ic0::call_funds_add(unit_blob.as_ptr() as u32, unit_blob.len() as u32, amount);
    }
}

/// Returns the argument extracted from the message payload.
pub fn arg_data() -> Vec<u8> {
    let len: u32 = unsafe { ic0::msg_arg_data_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_arg_data_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

/// Returns the caller of the current call.
pub fn caller() -> Vec<u8> {
    let len: u32 = unsafe { ic0::msg_caller_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_caller_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

/// Returns this canister's id as a blob.
pub fn id() -> CanisterId {
    let len: u32 = unsafe { ic0::canister_self_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::canister_self_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    CanisterId::try_from(bytes).unwrap()
}

/// Returns the controller of the canister as a blob.
pub fn controller() -> PrincipalId {
    let len: u32 = unsafe { ic0::controller_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::controller_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    PrincipalId::try_from(bytes.as_slice()).unwrap()
}

/// Returns the rejection message.
pub fn reject_message() -> String {
    let len: u32 = unsafe { ic0::msg_reject_msg_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_reject_msg_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    String::from_utf8_lossy(&bytes).to_string()
}

/// Replies with the given byte array.
/// Note, currently we do not support chunkwise assembling of the response.
pub fn reply(payload: &[u8]) {
    unsafe {
        ic0::msg_reply_data_append(payload.as_ptr() as u32, payload.len() as u32);
        ic0::msg_reply();
    }
}

/// Indicates that `amount` of funds of specified `unit` should be accepted in
/// the current message.
pub fn msg_funds_accept(unit: TokenUnit, amount: u64) {
    let unit_blob: Vec<u8> = unit.into();
    unsafe {
        ic0::msg_funds_accept(unit_blob.as_ptr() as u32, 1, amount);
    }
}

/// Rejects the current call with the given message.
pub fn reject(err_message: &str) {
    let err_message = err_message.as_bytes();
    unsafe {
        ic0::msg_reject(err_message.as_ptr() as u32, err_message.len() as u32);
    }
}

/// Returns the rejection code.
pub fn reject_code() -> i32 {
    unsafe { ic0::msg_reject_code() }
}

/// Prints the given message.
pub fn print<S: std::convert::AsRef<str>>(s: S) {
    let s = s.as_ref();
    unsafe {
        ic0::debug_print(s.as_ptr() as u32, s.len() as u32);
    }
}

/// Traps with the given message.
pub fn trap_with(message: &str) {
    unsafe {
        ic0::trap(message.as_ptr() as u32, message.len() as u32);
    }
}

pub fn now() -> SystemTime {
    let nanos_time = unsafe { ic0::time() };
    let duration = Duration::from_nanos(nanos_time);
    UNIX_EPOCH + duration
}

/// Represents the diffent token units that are available on canisters.
pub enum TokenUnit {
    Cycles = 0,
    ICP = 1,
}

/// Based on the public spec, cycles is represented by `0x00` and ICP tokens by
/// `0x01`.
impl Into<Vec<u8>> for TokenUnit {
    fn into(self) -> Vec<u8> {
        match self {
            TokenUnit::Cycles => hex::decode("00").unwrap(),
            TokenUnit::ICP => hex::decode("01").unwrap(),
        }
    }
}

/// Returns the amount of cycles in the canister's account.
pub fn canister_balance(unit: TokenUnit) -> u64 {
    let unit_blob: Vec<u8> = unit.into();
    unsafe { ic0::canister_balance(unit_blob.as_ptr() as u32, unit_blob.len() as u32) }
}

/// Returns the amount of funds available in this current message.
pub fn msg_funds_available(unit: TokenUnit) -> u64 {
    let unit_blob: Vec<u8> = unit.into();
    unsafe { ic0::msg_funds_available(unit_blob.as_ptr() as u32, unit_blob.len() as u32) }
}

/// Returns the amount of funds refunded with a response.
pub fn msg_funds_refunded(unit: TokenUnit) -> u64 {
    let unit_blob: Vec<u8> = unit.into();
    unsafe { ic0::msg_funds_refunded(unit_blob.as_ptr() as u32, unit_blob.len() as u32) }
}

/// Sets the certified data of this canister.
///
/// # Panics
///
/// * This function traps if data.len() > 32.
pub fn set_certified_data(data: &[u8]) {
    unsafe { ic0::certified_data_set(data.as_ptr() as u32, data.len() as u32) }
}

/// When called from a query call, returns the data certificate authenticating
/// certified_data set by this canister.
///
/// Returns None if called not from a query call.
pub fn data_certificate() -> Option<Vec<u8>> {
    if unsafe { ic0::data_certificate_present() } == 0 {
        return None;
    }

    let n = unsafe { ic0::data_certificate_size() };
    let mut buf = vec![0u8; n as usize];
    unsafe {
        ic0::data_certificate_copy(buf.as_mut_ptr() as u32, 0u32, n);
    }
    Some(buf)
}
