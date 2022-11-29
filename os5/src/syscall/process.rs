//! Process management syscalls

use crate::config::{MAX_SYSCALL_NUM, PAGE_SIZE};
use crate::loader::get_app_data_by_name;
use crate::mm::{translated_refmut, translated_str, virtaddr2phyaddr, VirtAddr};
use crate::task::{
    add_task, current_task, current_user_token, exit_current_and_run_next, get_cur_start_time,
    get_cur_syscall, mmap, munmap, suspend_current_and_run_next, TaskStatus,
};
use crate::timer::get_time_us;
use alloc::sync::Arc;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    debug!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    current_task().unwrap().pid.0 as isize
}

/// Syscall Fork which returns 0 for child process and child_pid for parent process
pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

/// Syscall Exec which accepts the elf path
pub fn sys_exec(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    // find a child process

    // ---- access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB lock exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after removing from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child TCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB lock automatically
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let virt_us: VirtAddr = (ts as usize).into();
    if let Some(pa) = virtaddr2phyaddr(virt_us) {
        let us = get_time_us();
        let phy_ts = pa.0 as *mut TimeVal;
        unsafe {
            *phy_ts = TimeVal {
                sec: us / 1_000_000,
                usec: us % 1_000_000,
            };
        }
        0
    } else {
        -1
    }
    // -1
}

// YOUR JOB: 引入虚地址后重写 sys_task_info
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let virt_ti: VirtAddr = (ti as usize).into();
    if let Some(pa) = virtaddr2phyaddr(virt_ti) {
        let now = get_time_us();
        let start = get_cur_start_time();
        let st = get_cur_syscall();
        let phy_ti = pa.0 as *mut TaskInfo;
        unsafe {
            *phy_ti = TaskInfo {
                status: TaskStatus::Running,
                syscall_times: st,
                time: (now - start) / 1_000,
            };
        }
        0
    } else {
        -1
    }
    // -1
}

// YOUR JOB: 实现sys_set_priority，为任务添加优先级
pub fn sys_set_priority(prio: isize) -> isize {
    if prio <= 1 {
        return -1;
    }
    let cur = current_task().unwrap();
    cur.inner_exclusive_access().set_prio(prio);
    prio
    // -1
}

// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    if start % 0x1000 != 0 {
        return -1;
    }
    if port & !0x7 != 0 || port == 0 {
        return -1;
    }
    let mut ll = len;
    if len % 0x1000 != 0 {
        ll = (len / PAGE_SIZE + 1) * PAGE_SIZE;
    }

    mmap(start, ll, port)
    // -1
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    if start % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
        return -1;
    }
    munmap(start, len)
    // -1
}

//
// YOUR JOB: 实现 sys_spawn 系统调用
// ALERT: 注意在实现 SPAWN 时不需要复制父进程地址空间，SPAWN != FORK + EXEC
pub fn sys_spawn(path: *const u8) -> isize {
    let cur = current_task().unwrap();
    let new_task = cur.spawn(path);
    if new_task.is_none() {
        return -1;
    }
    let new_task = new_task.unwrap();
    let new_pid = new_task.pid.0;
    // add_task(new_task);
    new_pid as isize
    // -1
}
