//! Implementation of [`TaskManager`]
//!
//! It is only used to manage processes and schedule process based on ready queue.
//! Other CPU process monitoring functions are in Processor.

use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;

pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

// YOUR JOB: FIFO->Stride
/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue.pop_front()
    }

    pub fn fetch_stride(&mut self) -> Option<Arc<TaskControlBlock>>{
        if self.ready_queue.is_empty(){
            return None;
        }
        let mut cur_stride = self.ready_queue.front().clone().unwrap().get_stride();
        let mut idx = 0;
        for (i, t) in self.ready_queue.iter().enumerate(){
            let s = t.get_stride();
            if s < cur_stride{
                cur_stride = s;
                idx = i;
            }
        }
        // let ret = self.ready_queue.get(idx).map(|t| Arc::clone(t));
        let ret = self.ready_queue.remove(idx);
        ret
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add(task);
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    // TASK_MANAGER.exclusive_access().fetch()
    TASK_MANAGER.exclusive_access().fetch_stride()
}
