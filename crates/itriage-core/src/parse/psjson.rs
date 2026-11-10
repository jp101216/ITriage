//! Reading the JSON that Windows PowerShell 5.1's `ConvertTo-Json` writes.
//!
//! It has two habits a strict reader trips over. A list with one item can
//! arrive as the bare item, and a list that PowerShell has wrapped arrives as
//! `{"value":[…],"Count":n}`. And anything can be `null`. These are
//! `deserialize_with` helpers that take every one of those forms.

use serde::de::{DeserializeOwned, Error};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// A list, however PowerShell wrote it: `[…]`, one bare item, the wrapped
/// form, or `null` (empty).
pub fn list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let items = match Value::deserialize(d)? {
        Value::Null => Vec::new(),
        Value::Array(a) => a,
        Value::Object(mut o) if o.len() == 2 && o.contains_key("value") && o.contains_key("Count") => {
            match o.remove("value") {
                Some(Value::Array(a)) => a,
                Some(Value::Null) | None => Vec::new(),
                Some(one) => vec![one],
            }
        }
        one => vec![one],
    };
    items.into_iter().map(|i| serde_json::from_value(i).map_err(D::Error::custom)).collect()
}

/// A value where `null` means "the default" (an empty string, zero, false).
pub fn or_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Debug, PartialEq, Default)]
    #[serde(default)]
    struct Doc {
        #[serde(deserialize_with = "list")]
        names: Vec<String>,
        #[serde(deserialize_with = "or_default")]
        note: String,
    }

    #[test]
    fn takes_every_shape_powershell_writes() {
        let names = |json: &str| serde_json::from_str::<Doc>(json).unwrap().names;
        assert_eq!(names(r#"{"names":["a","b"]}"#), ["a", "b"]);
        assert_eq!(names(r#"{"names":"a"}"#), ["a"], "one item arrives bare");
        assert_eq!(names(r#"{"names":{"value":["a","b"],"Count":2}}"#), ["a", "b"], "the wrapped form");
        assert_eq!(names(r#"{"names":{"value":"a","Count":1}}"#), ["a"]);
        assert!(names(r#"{"names":null}"#).is_empty());
        assert!(names("{}").is_empty());
        assert_eq!(serde_json::from_str::<Doc>(r#"{"note":null}"#).unwrap().note, "");
        assert!(serde_json::from_str::<Doc>(r#"{"names":[1]}"#).is_err(), "a wrong item type is still an error");
    }
}
