//! Poison-tolerant lock helpers.
//!
//! A panic while a lock is held (caught per message by the worker) must not
//! take the whole proxy down with it: the protected data is still usable, so
//! every lock in the workspace recovers the guard from a poisoned lock.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Locks `m`, recovering the guard if a previous holder panicked.
#[inline]
pub fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Read-locks `l`, recovering the guard if a previous writer panicked.
#[inline]
pub fn read<T: ?Sized>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

/// Write-locks `l`, recovering the guard if a previous writer panicked.
#[inline]
pub fn write<T: ?Sized>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn recovers_from_poison() {
        let m = Arc::new(Mutex::new(1));
        let m2 = m.clone();
        let r = std::thread::spawn(move || {
            let _g = m2.lock();
            panic!("poison");
        })
        .join();
        assert!(r.is_err());
        assert!(m.is_poisoned());
        *lock(&m) += 1;
        assert_eq!(*lock(&m), 2);

        let l = Arc::new(RwLock::new(1));
        let l2 = l.clone();
        let r = std::thread::spawn(move || {
            let _g = l2.write();
            panic!("poison");
        })
        .join();
        assert!(r.is_err());
        *write(&l) += 1;
        assert_eq!(*read(&l), 2);
    }
}
