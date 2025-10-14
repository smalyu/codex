use codex_core::config::Config;

mod director;
mod solver;
mod verifier;

pub(crate) use director::DIRECTOR_PROMPT;
pub(crate) use solver::SOLVER_PROMPT;
pub(crate) use verifier::VERIFIER_PROMPT;

pub fn ensure_instructions(role: &str, config: &mut Config) {
    if config.base_instructions.is_none()
        && let Some(text) = default_instructions_for_role(role)
    {
        config.base_instructions = Some(text.to_string());
    }
}

fn default_instructions_for_role(role: &str) -> Option<&'static str> {
    let normalized = role.to_ascii_lowercase();
    if normalized == "solver" {
        Some(SOLVER_PROMPT)
    } else if normalized == "director" {
        Some(DIRECTOR_PROMPT)
    } else if normalized.starts_with("verifier") {
        Some(VERIFIER_PROMPT)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_test_support::load_default_config_for_test;
    use tempfile::TempDir;

    #[test]
    fn provides_prompts_for_known_roles() {
        let home = TempDir::new().unwrap();
        let mut config = load_default_config_for_test(&home);
        config.base_instructions = None;
        ensure_instructions("solver", &mut config);
        assert!(
            config
                .base_instructions
                .as_ref()
                .unwrap()
                .contains("Codex Infty Solver")
        );

        let home = TempDir::new().unwrap();
        let mut config = load_default_config_for_test(&home);
        config.base_instructions = None;
        ensure_instructions("director", &mut config);
        assert!(
            config
                .base_instructions
                .as_ref()
                .unwrap()
                .contains("Codex Infty Director")
        );

        let home = TempDir::new().unwrap();
        let mut config = load_default_config_for_test(&home);
        config.base_instructions = None;
        ensure_instructions("verifier-alpha", &mut config);
        assert!(
            config
                .base_instructions
                .as_ref()
                .unwrap()
                .contains("Codex Infty Verifier")
        );
    }

    #[test]
    fn does_not_override_existing_instructions() {
        let home = TempDir::new().unwrap();
        let mut config = load_default_config_for_test(&home);
        config.base_instructions = Some("custom".to_string());
        ensure_instructions("solver", &mut config);
        assert_eq!(config.base_instructions.as_deref(), Some("custom"));
    }
}
