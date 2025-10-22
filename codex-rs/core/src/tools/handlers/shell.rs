use async_trait::async_trait;
use codex_protocol::models::ShellToolCallParams;
use std::sync::Arc;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::exec::ExecParams;
use crate::exec_env::CODEX_SESSION_ID_ENV_VAR;
use crate::exec_env::create_env;
use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::handle_container_exec_with_params;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub struct ShellHandler;

impl ShellHandler {
    fn to_exec_params(
        params: ShellToolCallParams,
        session: &Session,
        turn_context: &TurnContext,
    ) -> ExecParams {
        let mut env = create_env(&turn_context.shell_environment_policy);
        env.insert(
            CODEX_SESSION_ID_ENV_VAR.to_string(),
            session.conversation_id().to_string(),
        );

        ExecParams {
            command: params.command,
            cwd: turn_context.resolve_path(params.workdir.clone()),
            timeout_ms: params.timeout_ms,
            env,
            with_escalated_permissions: params.with_escalated_permissions,
            justification: params.justification,
            arg0: None,
        }
    }
}

#[async_trait]
impl ToolHandler for ShellHandler {
    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    fn matches_kind(&self, payload: &ToolPayload) -> bool {
        matches!(
            payload,
            ToolPayload::Function { .. } | ToolPayload::LocalShell { .. }
        )
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            tracker,
            call_id,
            tool_name,
            payload,
        } = invocation;

        match payload {
            ToolPayload::Function { arguments } => {
                let params: ShellToolCallParams =
                    serde_json::from_str(&arguments).map_err(|e| {
                        FunctionCallError::RespondToModel(format!(
                            "failed to parse function arguments: {e:?}"
                        ))
                    })?;
                let exec_params = Self::to_exec_params(params, session.as_ref(), turn.as_ref());
                let content = handle_container_exec_with_params(
                    tool_name.as_str(),
                    exec_params,
                    Arc::clone(&session),
                    Arc::clone(&turn),
                    Arc::clone(&tracker),
                    call_id.clone(),
                )
                .await?;
                Ok(ToolOutput::Function {
                    content,
                    success: Some(true),
                })
            }
            ToolPayload::LocalShell { params } => {
                let exec_params = Self::to_exec_params(params, session.as_ref(), turn.as_ref());
                let content = handle_container_exec_with_params(
                    tool_name.as_str(),
                    exec_params,
                    Arc::clone(&session),
                    Arc::clone(&turn),
                    Arc::clone(&tracker),
                    call_id.clone(),
                )
                .await?;
                Ok(ToolOutput::Function {
                    content,
                    success: Some(true),
                })
            }
            _ => Err(FunctionCallError::RespondToModel(format!(
                "unsupported payload for shell handler: {tool_name}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex::make_session_and_context;
    use pretty_assertions::assert_eq;

    #[test]
    fn to_exec_params_includes_session_id() {
        let (session, turn) = make_session_and_context();
        let expected_session_id = session.conversation_id().to_string();

        let params = ShellToolCallParams {
            command: vec!["echo".to_string()],
            workdir: None,
            timeout_ms: None,
            with_escalated_permissions: None,
            justification: None,
        };

        let exec_params = ShellHandler::to_exec_params(params, &session, &turn);

        assert_eq!(
            exec_params.env.get(CODEX_SESSION_ID_ENV_VAR),
            Some(&expected_session_id)
        );
    }
}
