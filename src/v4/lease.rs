//! Optional lease heartbeats use a separate session for the same client ID.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Default)]
pub(crate) struct LeaseHealth(AtomicBool);

impl LeaseHealth {
    pub(crate) fn fail(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub(crate) fn failed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(feature = "blocking")]
#[derive(Debug)]
pub(crate) struct BlockingLease {
    health: Arc<LeaseHealth>,
    stop: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
    session_id: super::proto::SessionId,
}

#[cfg(feature = "blocking")]
impl BlockingLease {
    pub(crate) fn start(
        interval: std::time::Duration,
        session_id: super::proto::SessionId,
        mut renew: impl FnMut() -> bool + Send + 'static,
    ) -> crate::Result<Self> {
        let health = Arc::new(LeaseHealth::default());
        let stop = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let worker_health = health.clone();
        let worker_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("nfs-lease".into())
            .spawn(move || {
                loop {
                    let (mutex, changed) = &*worker_stop;
                    let stopped = mutex.lock().unwrap();
                    let (stopped, _) = changed
                        .wait_timeout_while(stopped, interval, |value| !*value)
                        .unwrap();
                    if *stopped {
                        break;
                    }
                    drop(stopped);
                    if !renew() {
                        worker_health.fail();
                        break;
                    }
                }
            })?;
        Ok(Self {
            health,
            stop,
            thread: Some(thread),
            session_id,
        })
    }

    pub(crate) fn failed(&self) -> bool {
        self.health.failed()
            || self
                .thread
                .as_ref()
                .is_some_and(|thread| thread.is_finished())
    }

    pub(crate) fn stop(mut self) -> super::proto::SessionId {
        *self.stop.0.lock().unwrap() = true;
        self.stop.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.session_id
    }
}

#[cfg(feature = "blocking")]
impl Drop for BlockingLease {
    fn drop(&mut self) {
        *self.stop.0.lock().unwrap() = true;
        self.stop.1.notify_all();
    }
}

#[cfg(feature = "tokio")]
#[derive(Debug)]
pub(crate) struct TokioLease {
    pub(crate) health: Arc<LeaseHealth>,
    pub(crate) task: ::tokio::task::JoinHandle<()>,
    pub(crate) session_id: super::proto::SessionId,
}

#[cfg(feature = "tokio")]
impl TokioLease {
    pub(crate) fn failed(&self) -> bool {
        self.health.failed() || self.task.is_finished()
    }

    pub(crate) async fn stop(mut self) -> super::proto::SessionId {
        self.task.abort();
        let _ = (&mut self.task).await;
        self.session_id
    }
}

#[cfg(feature = "tokio")]
impl Drop for TokioLease {
    fn drop(&mut self) {
        self.task.abort();
    }
}
