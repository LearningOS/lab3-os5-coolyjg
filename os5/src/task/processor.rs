//! Implementation of [`Processor`] and Intersection of control flow
//!
//! Here, the continuous operation of user apps in CPU is maintained,
//! the current running state of CPU is recorded,
//! and the replacement and transfer of control flow of different applications are executed.

use super::__switch;
use super::{fetch_task, TaskStatus};
use super::{TaskContext, TaskControlBlock};
use crate::config::{BIG_STRIDE, MAX_SYSCALL_NUM};
use crate::mm::{MapPermission, VirtAddr, VirtPageNum};
use crate::sync::UPSafeCell;
use crate::timer::get_time_us;
use crate::trap::TrapContext;
use alloc::sync::Arc;
use lazy_static::*;

/// Processor management structure
pub struct Processor {
    /// The task currently executing on the current processor
    current: Option<Arc<TaskControlBlock>>,
    /// The basic control flow of each core, helping to select and switch process
    idle_task_cx: TaskContext,
}

impl Processor {
    pub fn new() -> Self {
        Self {
            current: None,
            idle_task_cx: TaskContext::zero_init(),
        }
    }
    fn get_idle_task_cx_ptr(&mut self) -> *mut TaskContext {
        &mut self.idle_task_cx as *mut _
    }
    pub fn take_current(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.current.take()
    }
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.current.as_ref().map(|task| Arc::clone(task))
    }
}

lazy_static! {
    /// PROCESSOR instance through lazy_static!
    pub static ref PROCESSOR: UPSafeCell<Processor> = unsafe { UPSafeCell::new(Processor::new()) };
}

/// The main part of process execution and scheduling
///
/// Loop fetch_task to get the process that needs to run,
/// and switch the process through __switch
pub fn run_tasks() {
    loop {
        let mut processor = PROCESSOR.exclusive_access();
        if let Some(task) = fetch_task() {
            let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
            // access coming task TCB exclusively
            let mut task_inner = task.inner_exclusive_access();
            if task_inner.task_start_time == 0 {
                task_inner.task_start_time = get_time_us();
            }
            task_inner.stride += task_inner.pass;
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            task_inner.task_status = TaskStatus::Running;
            drop(task_inner);
            // release coming task TCB manually
            processor.current = Some(task);
            // release processor manually
            drop(processor);
            unsafe {
                __switch(idle_task_cx_ptr, next_task_cx_ptr);
            }
        }
    }
}

/// Get current task through take, leaving a None in its place
pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().take_current()
}

/// Get a copy of the current task
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().current()
}

/// Get token of the address space of current task
pub fn current_user_token() -> usize {
    let task = current_task().unwrap();
    let token = task.inner_exclusive_access().get_user_token();
    token
}

/// Get the mutable reference to trap context of current task
pub fn current_trap_cx() -> &'static mut TrapContext {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_trap_cx()
}

/// Return to idle control flow for new scheduling
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = PROCESSOR.exclusive_access();
    let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
    drop(processor);
    unsafe {
        __switch(switched_task_cx_ptr, idle_task_cx_ptr);
    }
}

pub fn get_cur_start_time() -> usize {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_start_time()
}

pub fn increase_cur_syscall(id: usize) {
    // PROCESSOR
    //     .exclusive_access()
    //     .increase_current_task_syscall(id);
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .increase_syscall_times(id);
}

pub fn get_cur_syscall() -> [u32; MAX_SYSCALL_NUM] {
    // PROCESSOR.exclusive_access().get_current_task_syscall()
    let mut ret = [0; MAX_SYSCALL_NUM];
    ret.copy_from_slice(
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .get_syscall_times()
            .as_slice(),
    );
    ret
}

pub fn mmap(start: usize, len: usize, port: usize) -> isize {
    let cur = current_task().unwrap();
    let mut inner = cur.inner_exclusive_access();
    let svpn = VirtPageNum::from(VirtAddr::from(start));
    let evpn = VirtAddr::from(start + len).ceil();
    for vpn in svpn.0..evpn.0 {
        if inner.memory_set.check_mapped(vpn.into()) {
            return -1;
        }
    }
    let permission = MapPermission::from_bits(((port << 1) | 0x10) as u8).unwrap();
    inner
        .memory_set
        .insert_framed_area(svpn.into(), evpn.into(), permission);
    0
}

pub fn munmap(start: usize, len: usize) -> isize {
    let cur = current_task().unwrap();
    let mut inner = cur.inner_exclusive_access();
    let svpn = VirtPageNum::from(VirtAddr::from(start));
    let evpn = VirtAddr::from(start + len).ceil();
    for vpn in svpn.0..evpn.0 {
        if inner.memory_set.check_unmapped(vpn.into()) {
            return -1;
        }
    }
    for vpn in svpn.0..evpn.0 {
        inner.memory_set.remove_vpn(vpn.into());
    }
    0
}
