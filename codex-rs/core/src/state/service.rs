use crate::RolloutRecorder;
use crate::exec_command::ExecSessionManager;
use crate::executor::Executor;
use crate::file_change_notifier::FileChangeCollector;
use crate::file_change_notifier::FileChangeWatcher;
use crate::mcp_connection_manager::McpConnectionManager;
use crate::unified_exec::UnifiedExecSessionManager;
use crate::user_notification::UserNotifier;
use tokio::sync::Mutex;

pub(crate) struct SessionServices {
    pub(crate) mcp_connection_manager: McpConnectionManager,
    pub(crate) session_manager: ExecSessionManager,
    pub(crate) unified_exec_manager: UnifiedExecSessionManager,
    pub(crate) notifier: UserNotifier,
    pub(crate) rollout: Mutex<Option<RolloutRecorder>>,
    pub(crate) user_shell: crate::shell::Shell,
    pub(crate) show_raw_agent_reasoning: bool,
    pub(crate) executor: Executor,
    pub(crate) file_change_collector: Option<FileChangeCollector>,
    pub(crate) _file_change_watcher: Option<FileChangeWatcher>,
}
