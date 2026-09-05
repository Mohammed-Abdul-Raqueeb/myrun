//! Transactional setup with LIFO rollback.
//!
//! Bringing a container up touches half a dozen kernel subsystems: a state
//! directory, a cgroup, a bridge, a veth pair, an IP lease, NAT rules and
//! finally a process.  If step five fails, steps one to four **must** be
//! undone or the host slowly fills up with orphaned interfaces and cgroups.
//!
//! Usage:
//!
//! ```ignore
//! let mut rb = Rollback::new();
//! let cg = cgroup::create(&id)?;
//! rb.push("cgroup", move || cgroup::remove(&id));
//! // ...
//! rb.commit();   // success: forget the undo actions
//! ```
//!
//! Dropping a non-committed `Rollback` runs every registered action in
//! reverse order.  Errors during rollback are logged but never mask the
//! original failure — that is the single most important property here.

type Action = Box<dyn FnMut() -> crate::error::Result<()>>;

pub struct Rollback {
    actions: Vec<(&'static str, Action)>,
    committed: bool,
}

impl Rollback {
    pub fn new() -> Rollback {
        Rollback {
            actions: Vec::new(),
            committed: false,
        }
    }

    /// Register an undo action.  `name` appears in logs.
    pub fn push<F>(&mut self, name: &'static str, f: F)
    where
        F: FnMut() -> crate::error::Result<()> + 'static,
    {
        crate::log_debug!("rollback: registered undo for {}", name);
        self.actions.push((name, Box::new(f)));
    }

    /// Everything succeeded — discard the undo actions.
    pub fn commit(&mut self) {
        self.committed = true;
        self.actions.clear();
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Run every registered action in reverse order.  Returns the names of
    /// the actions that failed.
    pub fn unwind(&mut self) -> Vec<String> {
        let mut failed = Vec::new();
        while let Some((name, mut f)) = self.actions.pop() {
            match f() {
                Ok(()) => crate::log_debug!("rollback: undid {}", name),
                Err(e) => {
                    crate::log_warn!("rollback: undo for {} failed: {}", name, e);
                    failed.push(format!("{}: {}", name, e));
                }
            }
        }
        failed
    }
}

impl Default for Rollback {
    fn default() -> Self {
        Rollback::new()
    }
}

impl Drop for Rollback {
    fn drop(&mut self) {
        if !self.committed && !self.actions.is_empty() {
            crate::log_info!("rolling back {} setup steps", self.actions.len());
            self.unwind();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn unwinds_in_reverse_order() {
        let log: Rc<RefCell<Vec<&'static str>>> = Rc::new(RefCell::new(Vec::new()));
        {
            let mut rb = Rollback::new();
            for name in ["a", "b", "c"] {
                let l = log.clone();
                rb.push(name, move || {
                    l.borrow_mut().push(name);
                    Ok(())
                });
            }
            assert_eq!(rb.len(), 3);
        } // dropped without commit
        assert_eq!(*log.borrow(), vec!["c", "b", "a"]);
    }

    #[test]
    fn commit_prevents_unwind() {
        let log: Rc<RefCell<Vec<&'static str>>> = Rc::new(RefCell::new(Vec::new()));
        {
            let mut rb = Rollback::new();
            let l = log.clone();
            rb.push("x", move || {
                l.borrow_mut().push("x");
                Ok(())
            });
            rb.commit();
            assert!(rb.is_empty());
        }
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn failing_action_does_not_stop_the_rest() {
        let log: Rc<RefCell<Vec<&'static str>>> = Rc::new(RefCell::new(Vec::new()));
        let mut rb = Rollback::new();
        let l = log.clone();
        rb.push("first", move || {
            l.borrow_mut().push("first");
            Ok(())
        });
        rb.push("boom", || Err(crate::error::Error::io("nope")));
        let failed = rb.unwind();
        assert_eq!(failed.len(), 1);
        assert!(failed[0].starts_with("boom"));
        assert_eq!(*log.borrow(), vec!["first"], "later actions still ran");
    }
}
