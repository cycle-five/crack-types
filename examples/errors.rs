//! # Error Handling Examples
//!
//! This module provides examples and additional documentation for the error handling
//! system in the `crack-types` crate.

use crack_types::http::parse_url;
use crack_types::{verify, CrackedError, CrackedResult};
use std::fmt;

/// Example of creating custom errors that can be converted to `CrackedError`
///
/// This demonstrates how to create your own error types that can be easily
/// converted to the library's error type.
#[derive(Debug, thiserror::Error)]
pub enum MyCustomError {
    #[error("Failed to connect to music service: {0}")]
    ConnectionError(String),

    #[error("Track not found: {0}")]
    NotFoundError(String),

    #[error("Invalid configuration: {0}")]
    ConfigError(String),
}

impl From<MyCustomError> for CrackedError {
    fn from(err: MyCustomError) -> Self {
        // Map your custom error to an appropriate CrackedError variant
        match err {
            MyCustomError::ConnectionError(msg) => {
                CrackedError::Other(std::borrow::Cow::Borrowed(Box::leak(msg.into_boxed_str())))
            }
            MyCustomError::NotFoundError(_) => CrackedError::NoTrackName,
            MyCustomError::ConfigError(_) => CrackedError::InvalidPermissions,
        }
    }
}

/// Example function showing error handling with custom error type
pub fn example_function(connect: bool) -> CrackedResult<String> {
    if !connect {
        return Err(MyCustomError::ConnectionError("Cannot connect".to_string()).into());
    }

    Ok("Connected successfully".to_string())
}

/// Example of using the `verify` utility function for error handling
pub fn example_verify() -> CrackedResult<i32> {
    let value: Option<i32> = Some(42);

    // The verify function converts an Option or Result to a CrackedResult
    // with the specified error if the condition is false
    let result = verify(value, CrackedError::NoQuery)?;

    Ok(result)
}

/// Example of using the Result type with `CrackedError`
pub fn example_url_parsing(url: &str) -> CrackedResult<()> {
    // Demonstrate how parsing errors are automatically converted
    let _parsed_url = parse_url(url)?;

    Ok(())
}

/// Example of creating an error context formatter
pub struct ErrorContext<E> {
    context: &'static str,
    source: E,
}

impl<E: fmt::Display> fmt::Display for ErrorContext<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.source)
    }
}

/// A helper function to add context to any error
pub fn with_context<T, E>(
    result: Result<T, E>,
    context: &'static str,
) -> Result<T, ErrorContext<E>> {
    result.map_err(|err| ErrorContext {
        context,
        source: err,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify, CrackedError};
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn test_custom_error_conversion() {
        let custom_err = MyCustomError::ConnectionError("Test error".to_string());
        let cracked_err: CrackedError = custom_err.into();

        // Verify the error was converted to the expected variant
        match cracked_err {
            CrackedError::Other(msg) => assert_eq!(msg, "Test error"),
            _ => panic!("Incorrect error conversion"),
        }
    }

    #[test]
    fn test_error_from_trait() {
        // Test io::Error conversion
        let io_err = IoError::new(ErrorKind::NotFound, "File not found");
        let cracked_err: CrackedError = io_err.into();

        match cracked_err {
            CrackedError::IO(_) => (), // Conversion worked correctly
            _ => panic!("IO error conversion failed"),
        }

        // Test url::ParseError conversion
        let result = "not a url".parse::<url::Url>();
        let url_err = result.unwrap_err();
        let cracked_err: CrackedError = url_err.into();

        match cracked_err {
            CrackedError::UrlParse(_) => (), // Conversion worked correctly
            _ => panic!("URL parse error conversion failed"),
        }
    }

    #[test]
    fn test_verify_utility() {
        // Test with Option
        let some_value: Option<i32> = Some(42);
        let result = verify(some_value, CrackedError::NoQuery);
        assert_eq!(result, Ok(42));

        let none_value: Option<i32> = None;
        let result = verify(none_value, CrackedError::NoQuery);
        assert_eq!(result, Err(CrackedError::NoQuery));

        // Test with Result
        let ok_result: Result<&str, &str> = Ok("success");
        let result = verify(ok_result, CrackedError::NoQuery);
        assert_eq!(result, Ok("success"));

        let err_result: Result<&str, &str> = Err("error");
        let result = verify(err_result, CrackedError::NoQuery);
        assert_eq!(result, Err(CrackedError::NoQuery));

        // Test with bool
        let result = verify(true, CrackedError::NoQuery);
        assert_eq!(result, Ok(true));

        let result = verify(false, CrackedError::NoQuery);
        assert_eq!(result, Err(CrackedError::NoQuery));
    }

    #[test]
    fn test_error_display() {
        // Test display implementation for various error types
        let errors = [
            CrackedError::NoQuery,
            CrackedError::EmptySearchResult,
            CrackedError::NoTrackName,
            CrackedError::NotInRange("volume", 110, 0, 100),
            CrackedError::Other("Custom error message"),
        ];

        for err in &errors {
            // Just check that display doesn't panic or return empty string
            let display = format!("{}", err);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_error_context() {
        let result: Result<(), &str> = Err("failed operation");
        let with_ctx = with_context(result, "While processing request");

        assert!(with_ctx.is_err());
        assert_eq!(
            format!("{}", with_ctx.unwrap_err()),
            "While processing request: failed operation"
        );
    }
}

fn main() {
    // Run tests
    println!("This is a test module and does not contain any executable code.");
}
