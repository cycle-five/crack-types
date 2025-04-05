//! # Error Handling
//!
//! This module provides a comprehensive implementation of the error handling system
//! for the Crack Types library. It includes a well-organized error type system,
//! utilities for error conversion, and comprehensive documentation.

use crate::messaging::messages::{
    COULD_NOT_FIND_PERMS, EMPTY_SEARCH_RESULT, FAIL_AUDIO_STREAM_RUSTY_YTDL_METADATA,
    FAIL_AUTHOR_DISCONNECTED, FAIL_AUTHOR_NOT_FOUND, FAIL_EMPTY_VECTOR, FAIL_INSERT,
    FAIL_INSERT_GUILD_SETTINGS, FAIL_INVALID_PERMS, FAIL_INVALID_TOPGG_TOKEN,
    FAIL_MISSING_BOT_PERMISSIONS, FAIL_MISSING_USER_PERMISSIONS, FAIL_NOTHING_PLAYING,
    FAIL_NOT_IMPLEMENTED, FAIL_NO_QUERY_PROVIDED, FAIL_NO_SONGBIRD, FAIL_NO_VIRUSTOTAL_API_KEY,
    FAIL_NO_VOICE_CONNECTION, FAIL_PARSE_TIME, FAIL_PLAYLIST_FETCH, FAIL_RESUME,
    FAIL_TO_SET_CHANNEL_SIZE, FAIL_WRONG_CHANNEL, GUILD_ONLY, MISSING_ENV_VAR,
    NOT_IN_MUSIC_CHANNEL, NO_CHANNEL_ID, NO_DATABASE_POOL, NO_GUILD_CACHED, NO_GUILD_ID,
    NO_GUILD_SETTINGS, NO_METADATA, NO_TRACK_NAME, NO_USER_AUTOPLAY, QUEUE_IS_EMPTY,
    ROLE_NOT_FOUND, SPOTIFY_AUTH_FAILED, UNAUTHORIZED_USER,
};
use crate::TrackResolveError;

use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::process::ExitStatus;

use poise::serenity_prelude::{ChannelId, GuildId};
use rspotify::ClientError as RSpotifyClientError;
use rusty_ytdl::VideoError;
use serenity::all::Permissions;
use serenity::model::mention::Mention;
use serenity::Error as SerenityError;
use songbird::error::JoinError;
use songbird::input::{AudioStreamError, AuxMetadataError};
use songbird::tracks::ControlError;
use tokio::time::error::Elapsed;
use thiserror::Error as ThisError;

/// Standard error type for the crate, using a boxed trait object
pub type Error = Box<dyn StdError + Send + Sync>;

/// A specialized Result type for Crack operations.
///
/// This is a type alias for `Result<T, CrackedError>`, which enables cleaner
/// signatures and error handling in the crate.
///
/// # Examples
///
/// ```rust
/// use crack_types::{CrackedResult, CrackedError};
///
/// fn example_function() -> CrackedResult<String> {
///     // Example implementation
///     if true {
///         Ok("Success".to_string())
///     } else {
///         Err(CrackedError::NotImplemented)
///     }
/// }
/// ```
pub type CrackedResult<T> = Result<T, CrackedError>;

/// The primary error type for the crack-types crate.
///
/// This enum represents all possible errors that can occur when using the crack-types
/// library. It is categorized into logical groups with standardized formatting for
/// better readability and organization.
///
/// # Implementation Note
///
/// The design uses the following principles:
/// - Organized by categories for better maintainability
/// - Standardized error message formatting
/// - Full error chain support through the `std::error::Error` trait
/// - Extensive From implementations for easy interoperability
#[derive(Debug, ThisError)]
pub enum CrackedError {
    //
    // Connection and Authorization errors
    //
    /// Indicates the user is already connected
    #[error("{FAIL_AUTHOR_NOT_FOUND} {0}")]
    AlreadyConnected(Mention),
    
    /// Indicates the author has disconnected
    #[error("{FAIL_AUTHOR_DISCONNECTED} {0}")]
    AuthorDisconnected(Mention),
    
    /// The author could not be found
    #[error("{FAIL_AUTHOR_NOT_FOUND}")]
    AuthorNotFound,
    
    /// Invalid permissions were provided
    #[error("{FAIL_INVALID_PERMS}")]
    InvalidPermissions,
    
    /// Not connected to a voice channel
    #[error("{FAIL_NO_VOICE_CONNECTION}")]
    NotConnected,
    
    /// User is not in the music channel
    #[error("{NOT_IN_MUSIC_CHANNEL} {0}")]
    NotInMusicChannel(ChannelId),
    
    /// User is not authorized to perform this action
    #[error("{UNAUTHORIZED_USER}")]
    UnauthorizedUser,
    
    /// Wrong voice channel was specified
    #[error("{FAIL_WRONG_CHANNEL}")]
    WrongVoiceChannel,
    
    /// Error when trying to join a channel
    #[error("{0}")]
    JoinChannelError(#[from] Box<JoinError>),

    //
    // Command and Input errors
    //
    /// A command failed to execute
    #[error("Command `{0}` failed with status `{1}` and output `{2}`")]
    CommandFailed(Cow<'static, str>, ExitStatus, Cow<'static, str>),
    
    /// Command was not found
    #[error("Command does not exist: {0}")]
    CommandNotFound(Cow<'static, str>),
    
    /// Failed to parse duration
    #[error("Failed to parse duration `{0}` and `{1}`")]
    DurationParseError(Cow<'static, str>, Cow<'static, str>),
    
    /// No query was provided
    #[error("{FAIL_NO_QUERY_PROVIDED}")]
    NoQuery,
    
    /// Search returned no results
    #[error("{EMPTY_SEARCH_RESULT}")]
    EmptySearchResult,
    
    /// A vector was unexpectedly empty
    #[error("{FAIL_EMPTY_VECTOR} {0}")]
    EmptyVector(Cow<'static, str>),
    
    /// Index out of bounds
    #[error("Index out of bounds for `{name}` at {index}")]
    IndexOutOfBounds {
        name: Cow<'static, str>,
        index: usize,
    },
    
    /// Invalid IP address
    #[error("Invalid ip {0}")]
    InvalidIP(Cow<'static, str>),
    
    /// Value not in valid range
    #[error("`{0}` should be between {2} and {3} but was {1}")]
    NotInRange(Cow<'static, str>, isize, isize, isize),

    //
    // Missing resource errors
    //
    /// Guild only operation
    #[error("{GUILD_ONLY}")]
    GuildOnly,
    
    /// No channel ID was provided
    #[error("{NO_CHANNEL_ID}")]
    NoChannelId,
    
    /// No database pool available
    #[error("{NO_DATABASE_POOL}")]
    NoDatabasePool,
    
    /// Guild not found in cache
    #[error("{NO_GUILD_CACHED}")]
    NoGuildCached,
    
    /// Guild ID not found
    #[error("{NO_GUILD_ID}")]
    NoGuildId,
    
    /// No guild found for channel ID
    #[error("No guild for channel id {0}")]
    NoGuildForChannelId(ChannelId),
    
    /// Guild settings not found
    #[error("{NO_GUILD_SETTINGS}")]
    NoGuildSettings,
    
    /// No log channel configured
    #[error("No log channel")]
    NoLogChannel,
    
    /// No metadata available
    #[error("{NO_METADATA}")]
    NoMetadata,
    
    /// No track name available
    #[error("{NO_TRACK_NAME}")]
    NoTrackName,
    
    /// No track is currently playing
    #[error("{FAIL_NOTHING_PLAYING}")]
    NoTrackPlaying,
    
    /// Nothing is currently playing
    #[error("{FAIL_NOTHING_PLAYING}")]
    NothingPlaying,
    
    /// No Songbird instance
    #[error("{FAIL_NO_SONGBIRD}")]
    NoSongbird,
    
    /// Top.gg token is invalid
    #[error("{FAIL_INVALID_TOPGG_TOKEN}")]
    InvalidTopGGToken,
    
    /// No VirusTotal API key configured
    #[error("{FAIL_NO_VIRUSTOTAL_API_KEY}")]
    NoVirusTotalApiKey,
    
    /// Role not found
    #[error("{ROLE_NOT_FOUND} {0}")]
    RoleNotFound(serenity::all::RoleId),
    
    /// Missing environment variable
    #[error("{MISSING_ENV_VAR} {0}")]
    MissingEnvVar(String),
    
    /// Missing user permissions
    #[error("{FAIL_MISSING_USER_PERMISSIONS}: {}", .0.as_ref().map_or_else(|| COULD_NOT_FIND_PERMS.to_string(), |p| p.to_string()))]
    MissingUserPermissions(Option<Permissions>),
    
    /// Missing bot permissions
    #[error("{FAIL_MISSING_BOT_PERMISSIONS}: {}", .0.as_ref().map_or_else(|| COULD_NOT_FIND_PERMS.to_string(), |p| p.to_string()))]
    MissingBotPermissions(Option<Permissions>),
    
    /// Log channel warning
    #[error("No log channel set for {0} in {1}")]
    LogChannelWarning(Cow<'static, str>, GuildId),
    
    /// No user autoplay configured
    #[error("{NO_USER_AUTOPLAY}")]
    NoUserAutoplay,

    //
    // Operation failures
    //
    /// Failed to resume playback
    #[error("{FAIL_RESUME}")]
    FailedResume,
    
    /// Failed to insert into database
    #[error("{FAIL_INSERT}")]
    FailedToInsert,
    
    /// Failed to insert guild settings
    #[error("{FAIL_INSERT_GUILD_SETTINGS}")]
    FailedToInsertGuildSettings,
    
    /// Failed to set channel size
    #[error("{FAIL_TO_SET_CHANNEL_SIZE} {0}, {1}, {2}\n{3}")]
    FailedToSetChannelSize(Cow<'static, str>, ChannelId, u32, Error),
    
    /// Playlist fetch failed
    #[error("{FAIL_PLAYLIST_FETCH}")]
    PlayListFail,
    
    /// Time parsing failed
    #[error("{FAIL_PARSE_TIME}")]
    ParseTimeFail,
    
    /// Queue is empty
    #[error("{QUEUE_IS_EMPTY}")]
    QueueEmpty,
    
    /// Not implemented
    #[error("{FAIL_NOT_IMPLEMENTED}")]
    NotImplemented,
    
    /// Unimplemented event
    #[error("Unimplemented event {1} for channel {0}")]
    UnimplementedEvent(ChannelId, Cow<'static, str>),

    //
    // External service errors
    //
    /// Audio stream error from Songbird
    #[error("{0}")]
    AudioStream(#[from] AudioStreamError),
    
    /// Audio stream metadata error from rusty_ytdl
    #[error("{FAIL_AUDIO_STREAM_RUSTY_YTDL_METADATA}")]
    AudioStreamRustyYtdlMetadata,
    
    /// Auxiliary metadata error
    #[error("{0}")]
    AuxMetadataError(#[from] AuxMetadataError),
    
    /// Track control error
    #[error("{0}")]
    Control(#[from] ControlError),
    
    /// rspotify client error
    #[error("{0}")]
    RSpotify(#[from] RSpotifyClientError),
    
    /// Lock error from rspotify
    #[error("rSpotify lock error: {0}")]
    RSpotifyLockError(Cow<'static, str>),
    
    /// Spotify authentication error
    #[error("{SPOTIFY_AUTH_FAILED}")]
    SpotifyAuth,
    
    /// Track resolution error
    #[error("{0}")]
    ResolveError(#[from] TrackResolveError),
    
    /// Video error from rusty_ytdl
    #[error("{0}")]
    VideoError(#[from] VideoError),

    //
    // Technical errors
    //
    /// General anyhow error
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
    
    /// Configuration for GPT features
    #[cfg(feature = "crack-gpt")]
    #[error("{0}")]
    CrackGPT(Error),
    
    /// IO error
    #[error("{0}")]
    IO(#[from] std::io::Error),
    
    /// Poison error from mutex
    #[error("{0}")]
    PoisonError(Error),
    
    /// Error from Poise library
    #[error("{0}")]
    Poise(Error),
    
    /// Reqwest HTTP error
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),
    
    /// JSON/Serde serialization error
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    
    /// Songbird error
    #[error("{0}")]
    Songbird(Error),
    
    /// Serenity error
    #[error("{0}")]
    Serenity(#[from] SerenityError),
    
    /// SQL error from SQLx
    #[error("{0}")]
    SQLX(#[from] sqlx::Error),
    
    /// Track failure
    #[error("{0}")]
    TrackFail(Error),
    
    /// URL parsing error
    #[error("{0}")]
    UrlParse(#[from] url::ParseError),

    //
    // General errors
    //
    /// Generic error with static string
    #[error("{0}")]
    Other(Cow<'static, str>),
}

// Custom implementations that can't be covered by thiserror

/// Safe marker for `CrackedError` to be sent between threads
unsafe impl Send for CrackedError {}

/// Safe marker for `CrackedError` to be shared between threads
unsafe impl Sync for CrackedError {}

/// Implementation of the `PartialEq` trait for the `CrackedError` enum.
///
/// This enables equality comparisons between `CrackedError` instances.
/// For most variants, only the discriminant (variant type) is compared.
/// For certain variants with inner values, the inner values are also compared.
impl PartialEq for CrackedError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Compare inner values for these variants
            (Self::Other(l0), Self::Other(r0)) => l0 == r0,
            (Self::NotInRange(l0, l1, l2, l3), Self::NotInRange(r0, r1, r2, r3)) => {
                l0 == r0 && l1 == r1 && l2 == r2 && l3 == r3
            }
            (Self::AuthorDisconnected(l0), Self::AuthorDisconnected(r0))
            | (Self::AlreadyConnected(l0), Self::AlreadyConnected(r0)) => {
                l0.to_string() == r0.to_string()
            }
            (Self::Serenity(l0), Self::Serenity(r0)) => format!("{:?}", l0) == format!("{:?}", r0),
            
            // For all other variants, only compare the discriminant (variant type)
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

// From implementations not covered by thiserror

impl From<CrackedError> for AudioStreamError {
    fn from(err: CrackedError) -> Self {
        AudioStreamError::Fail(Box::new(err))
    }
}

impl From<Error> for CrackedError {
    fn from(err: Error) -> Self {
        CrackedError::Poise(err)
    }
}

impl From<CrackedError> for SerenityError {
    fn from(_err: CrackedError) -> Self {
        SerenityError::Io(std::io::Error::other("CrackedError"))
    }
}

impl From<Elapsed> for CrackedError {
    fn from(_: Elapsed) -> Self {
        CrackedError::Other(Cow::Borrowed("Timeout"))
    }
}

impl From<&'static str> for CrackedError {
    fn from(err: &'static str) -> Self {
        CrackedError::Other(Cow::Borrowed(err))
    }
}

/// Helper for working with boolean-like types in error handling.
///
/// This trait provides a unified way to test if a value is "truthy" and to extract
/// its inner value. It's implemented for common types like `bool`, `Option<T>`,
/// and `Result<T, E>`.
pub trait Verifiable<T> {
    /// Tests if the value represents a "truthy" state
    fn to_bool(&self) -> bool;
    
    /// Extracts the inner value, panicking if not in a "truthy" state
    fn unpack(self) -> T;
}

impl Verifiable<bool> for bool {
    fn to_bool(&self) -> bool {
        *self
    }

    fn unpack(self) -> bool {
        self
    }
}

impl<T> Verifiable<T> for Option<T> {
    fn to_bool(&self) -> bool {
        self.is_some()
    }

    fn unpack(self) -> T {
        self.unwrap()
    }
}

impl<T, E> Verifiable<T> for Result<T, E>
where
    E: Debug,
{
    fn to_bool(&self) -> bool {
        self.is_ok()
    }

    fn unpack(self) -> T {
        self.unwrap()
    }
}

/// Verifies a condition and produces either the extracted value or a specific error.
///
/// This utility function simplifies the pattern of checking if a condition is true
/// and returning either the valid value or a specific error.
///
/// # Examples
///
/// ```
/// use crack_types::{verify, CrackedError};
///
/// let optional: Option<i32> = Some(42);
/// let result = verify(optional, CrackedError::NotImplemented)?;
/// assert_eq\!(result, 42);
///
/// let bool_val = true;
/// let result = verify(bool_val, CrackedError::NotImplemented)?;
/// assert_eq\!(result, true);
/// # Ok::<(), CrackedError>(())
/// ```
///
/// # Errors
/// 
/// Returns `Err(err)` if the condition is false (or equivalent).
pub fn verify<K, T: Verifiable<K>>(verifiable: T, err: CrackedError) -> CrackedResult<K> {
    if verifiable.to_bool() {
        Ok(verifiable.unpack())
    } else {
        Err(err)
    }
}

/// Provides a convenient extension trait for adding context to errors
pub trait ErrorExt<T> {
    /// Adds a static string context to the error
    /// 
    /// # Errors
    /// 
    /// Returns `Err(CrackedError::Other(msg))` if the result contains an error
    fn context(self, ctx: &'static str) -> CrackedResult<T>;
    
    /// Maps any error type to CrackedError::Other with the given message
    /// 
    /// # Errors
    /// 
    /// Returns `Err(CrackedError::Other(msg))` if the result contains an error
    fn map_err_to_other(self, msg: &'static str) -> CrackedResult<T>;
}

impl<T, E: Into<CrackedError>> ErrorExt<T> for Result<T, E> {
    fn context(self, ctx: &'static str) -> CrackedResult<T> {
        self.map_err(|e| {
            let err = e.into();
            CrackedError::Other(Cow::Owned(format!("{}: {}", ctx, err)))
        })
    }
    
    fn map_err_to_other(self, msg: &'static str) -> CrackedResult<T> {
        self.map_err(|_| CrackedError::Other(Cow::Borrowed(msg)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn test_verify() {
        let ok = verify(true, CrackedError::NoGuildCached);
        assert_eq!(ok, Ok(true));

        let err = verify(false, CrackedError::NoGuildCached);
        assert_eq!(err, Err(CrackedError::NoGuildCached));

        let ok = verify(Some(1), CrackedError::NoGuildCached);
        assert_eq!(ok, Ok(1));

        let x: Option<i32> = None;
        let err = verify(x, CrackedError::NoGuildCached);
        assert_eq!(err, Err(CrackedError::NoGuildCached));

        let ok = verify(Ok::<i32, CrackedError>(1), CrackedError::NoGuildCached);
        assert_eq!(ok, Ok(1));
    }

    #[test]
    fn test_error_context() {
        let result: Result<(), std::io::Error> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound, 
            "file not found"
        ));
        
        let with_context = result.context("Failed to read configuration");
        assert!(with_context.is_err());
        
        match with_context {
            Err(CrackedError::Other(msg)) => {
                assert!(msg.contains("Failed to read configuration"));
                assert!(msg.contains("file not found"));
            },
            _ => panic!("Expected Other error variant with context"),
        }
    }

    #[test]
    fn test_error_display() {
        // Test a few sample error variants
        let errors = [
            CrackedError::NoGuildCached,
            CrackedError::NoGuildId,
            CrackedError::NoGuildSettings,
            CrackedError::NoLogChannel,
            CrackedError::NoUserAutoplay,
            CrackedError::WrongVoiceChannel,
            CrackedError::NothingPlaying,
            CrackedError::PlayListFail,
            CrackedError::ParseTimeFail,
            CrackedError::UnauthorizedUser,
            CrackedError::NotInRange(Cow::Borrowed("test"), 1, 2, 3),
        ];
        
        // Just verify that all error variants can be formatted without panicking
        for err in &errors {
            let display = format!("{}", err);
            assert!(!display.is_empty(), "Error display should not be empty");
        }
    }
    
    #[test]
    fn test_error_source() {
        // Test error source chain for wrapped errors
        let io_err = std::io::Error::new(ErrorKind::NotFound, "test error");
        let cracked_err = CrackedError::IO(io_err);
        
        // Should have a source
        assert!(cracked_err.source().is_some());
        
        // The source should be the io error
        let source = cracked_err.source().unwrap();
        assert_eq!(source.to_string(), "test error");
    }
    
    #[test]
    fn test_map_err_to_other() {
        let result: Result<(), &str> = Err("failed");
        let mapped = result.map_err_to_other("Operation failed");
        
        assert!(mapped.is_err());
        match mapped {
            Err(CrackedError::Other(msg)) => {
                assert_eq!(msg, "Operation failed");
            },
            _ => panic!("Expected Other error variant"),
        }
    }
}
