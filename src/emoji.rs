use std::collections::HashMap;
use std::sync::LazyLock;

/// Map of emoji shortcode → unicode character, embedded at compile time.
/// Source: https://github.com/binwiederhier/ntfy/blob/main/server/mailer_emoji_map.json
static EMOJI_MAP_STR: &str = include_str!("emoji_map.json");

static EMOJI_MAP: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    serde_json::from_str(EMOJI_MAP_STR).unwrap_or_default()
});

/// Replace emoji shortcodes in tags with their unicode equivalents.
/// Tags that are already unicode emoji pass through unchanged.
pub fn resolve_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|tag| {
            if let Some(emoji) = EMOJI_MAP.get(tag) {
                emoji.clone()
            } else {
                tag.clone()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_shortcode() {
        let tags = vec!["white_check_mark".to_string(), "rotating_light".to_string()];
        let resolved = resolve_tags(&tags);
        assert_eq!(resolved, vec!["✅", "🚨"]);
    }

    #[test]
    fn test_passthrough_unicode() {
        let tags = vec!["✅".to_string(), "🚨".to_string()];
        let resolved = resolve_tags(&tags);
        assert_eq!(resolved, vec!["✅", "🚨"]);
    }

    #[test]
    fn test_unknown_shortcode_passthrough() {
        let tags = vec!["not_a_real_emoji".to_string()];
        let resolved = resolve_tags(&tags);
        assert_eq!(resolved, vec!["not_a_real_emoji"]);
    }

    #[test]
    fn test_emoji_map_loaded() {
        assert!(!EMOJI_MAP.is_empty());
        assert_eq!(EMOJI_MAP.get("+1").unwrap(), "👍");
    }
}
