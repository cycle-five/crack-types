//! # Error Handling
//!
//! This module provides an improved implementation of the error handling system
//! for the Crack Types library. It includes enhancements to the existing `CrackedError`
//! design, additional utilities, and comprehensive documentation.

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
use std::fmt::{self, Debug, Display};
use std::process::ExitStatus;

use poise::serenity_prelude::{ChannelId, GuildId, Mentionable};
use rspotify::ClientError as RSpotifyClientError;
use rusty_ytdl::VideoError;
use serenity::all::Permissions;
use serenity::model::mention::Mention;
use serenity::Error as SerenityError;
use songbird::error::JoinError;
use songbird::input::{AudioStreamError, AuxMetadataError};
use songbird::tracks::ControlError;
use tokio::time::error::Elapsed;

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
/// use crack_types::errors::{CrackedResult, CrackedError};
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
#[derive(Debug)]
pub enum CrackedError {
    //
    // Connection and Authorization errors
    //
    /// Indicates the user is already connected
    AlreadyConnected(Mention),
    /// Indicates the author has disconnected
    AuthorDisconnected(Mention),
    /// The author could not be found
    AuthorNotFound,
    /// Invalid permissions were provided
    InvalidPermissions,
    /// Not connected to a voice channel
    NotConnected,
    /// User is not in the music channel
    NotInMusicChannel(ChannelId),
    /// User is not authorized to perform this action
    UnauthorizedUser,
    /// Wrong voice channel was specified
    WrongVoiceChannel,
    /// Error when trying to join a channel
    JoinChannelError(Box<JoinError>),

    //
    // Command and Input errors
    //
    /// A command failed to execute
    CommandFailed(Cow<'static, str>, ExitStatus, Cow<'static, str>),
    /// Command was not found
    CommandNotFound(Cow<'static, str>),
    /// Failed to parse duration
    DurationParseError(Cow<'static, str>, Cow<'static, str>),
    /// No query was provided
    NoQuery,
    /// Search returned no results
    EmptySearchResult,
    /// A vector was unexpectedly empty
    EmptyVector(Cow<'static, str>),
    /// Index out of bounds
    IndexOutOfBounds {
        name: Cow<'static, str>,
        index: usize,
    },
    /// Invalid IP address
    InvalidIP(Cow<'static, str>),
    /// Value not in valid range
    NotInRange(Cow<'static, str>, isize, isize, isize),

    //
    // Missing resource errors
    //
    /// Guild only operation
    GuildOnly,
    /// No channel ID was provided
    NoChannelId,
    /// No database pool available
    NoDatabasePool,
    /// Guild not found in cache
    NoGuildCached,
    /// Guild ID not found
    NoGuildId,
    /// No guild found for channel ID
    NoGuildForChannelId(ChannelId),
    /// Guild settings not found
    NoGuildSettings,
    /// No log channel configured
    NoLogChannel,
    /// No metadata available
    NoMetadata,
    /// No track name available
    NoTrackName,
    /// No track is currently playing
    NoTrackPlaying,
    /// Nothing is currently playing
    NothingPlaying,
    /// No Songbird instance
    NoSongbird,
    /// Top.gg token is invalid
    InvalidTopGGToken,
    /// No VirusTotal API key configured
    NoVirusTotalApiKey,
    /// Role not found
    RoleNotFound(serenity::all::RoleId),
    /// Missing environment variable
    MissingEnvVar(String),
    /// Missing user permissions
    MissingUserPermissions(Option<Permissions>),
    /// Missing bot permissions
    MissingBotPermissions(Option<Permissions>),
    /// Log channel warning
    LogChannelWarning(Cow<'static, str>, GuildId),
    /// No user autoplay configured
    NoUserAutoplay,

    //
    // Operation failures
    //
    /// Failed to resume playback
    FailedResume,
    /// Failed to insert into database
    FailedToInsert,
    /// Failed to insert guild settings
    FailedToInsertGuildSettings,
    /// Failed to set channel size
    FailedToSetChannelSize(Cow<'static, str>, ChannelId, u32, Error),
    /// Playlist fetch failed
    PlayListFail,
    /// Time parsing failed
    ParseTimeFail,
    /// Queue is empty
    QueueEmpty,
    /// Not implemented
    NotImplemented,
    /// Unimplemented event
    UnimplementedEvent(ChannelId, Cow<'static, str>),

    //
    // External service errors
    //
    /// Audio stream error from Songbird
    AudioStream(AudioStreamError),
    /// Audio stream metadata error from rusty_ytdl
    AudioStreamRustyYtdlMetadata,
    /// Auxiliary metadata error
    AuxMetadataError(AuxMetadataError),
    /// Track control error
    Control(ControlError),
    /// rspotify client error
    RSpotify(RSpotifyClientError),
    /// Lock error from rspotify
    RSpotifyLockError(Cow<'static, str>),
    /// Spotify authentication error
    SpotifyAuth,
    /// Track resolution error
    ResolveError(TrackResolveError),
    /// Video error from rusty_ytdl
    VideoError(VideoError),

    //
    // Technical errors
    //
    /// General anyhow error
    Anyhow(anyhow::Error),
    /// Configuration for GPT features
    #[cfg(feature = "crack-gpt")]
    CrackGPT(Error),
    /// IO error
    IO(std::io::Error),
    /// Poison error from mutex
    PoisonError(Error),
    /// Error from Poise library
    Poise(Error),
    /// Reqwest HTTP error
    Reqwest(reqwest::Error),
    /// JSON serialization error
    Json(serde_json::Error),
    /// Serde serialization error
    Serde(serde_json::Error),
    /// Songbird error
    Songbird(Error),
    /// Serenity error
    Serenity(SerenityError),
    /// SQL error from SQLx
    SQLX(sqlx::Error),
    /// Track failure
    TrackFail(Error),
    /// URL parsing error
    UrlParse(url::ParseError),

    //
    // General errors
    //
    /// Generic error with static string
    Other(Cow<'static, str>),
}

impl std::error::Error for CrackedError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::AudioStream(err) => Some(err),
            Self::AuxMetadataError(err) => Some(err),
            Self::Anyhow(err) => Some(err.as_ref()),
            #[cfg(feature = "crack-gpt")]
            Self::CrackGPT(err) => Some(err.as_ref()),
            Self::Control(err) => Some(err),
            Self::FailedToSetChannelSize(_, _, _, err) => Some(err.as_ref()),
            Self::IO(err) => Some(err),
            Self::JoinChannelError(err) => Some(err.as_ref()),
            Self::Json(err) => Some(err),
            Self::PoisonError(err) => Some(err.as_ref()),
            Self::Poise(err) => Some(err.as_ref()),
            Self::Reqwest(err) => Some(err),
            Self::RSpotify(err) => Some(err),
            Self::Songbird(err) => Some(err.as_ref()),
            Self::SQLX(err) => Some(err),
            Self::Serde(err) => Some(err),
            Self::ResolveError(err) => Some(err),
            Self::Serenity(err) => Some(err),
            Self::TrackFail(err) => Some(err.as_ref()),
            Self::UrlParse(err) => Some(err),
            Self::VideoError(err) => Some(err),
            _ => None,
        }
    }
}

/// Safe marker for `CrackedError` to be sent between threads
unsafe impl Send for CrackedError {}

/// Safe marker for `CrackedError` to be shared between threads
unsafe impl Sync for CrackedError {}

/// Implementation of the `Display` trait for the `CrackedError` enum.
///
/// This formats error messages that will be sent as responses to Discord interactions.
impl Display for CrackedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Connection and authorization errors
            Self::AlreadyConnected(mention) => {
                f.write_fmt(format_args!("{FAIL_AUTHOR_NOT_FOUND} {mention}"))
            }
            Self::AuthorDisconnected(mention) => {
                f.write_fmt(format_args!("{FAIL_AUTHOR_DISCONNECTED} {mention}"))
            }
            Self::AuthorNotFound => f.write_str(FAIL_AUTHOR_NOT_FOUND),
            Self::InvalidPermissions => f.write_str(FAIL_INVALID_PERMS),
            Self::NotConnected => f.write_str(FAIL_NO_VOICE_CONNECTION),
            Self::NotInMusicChannel(channel_id) => f.write_fmt(format_args!(
                "{NOT_IN_MUSIC_CHANNEL} {}",
                channel_id.mention()
            )),
            Self::UnauthorizedUser => f.write_str(UNAUTHORIZED_USER),
            Self::WrongVoiceChannel => f.write_str(FAIL_WRONG_CHANNEL),
            Self::JoinChannelError(err) => write!(f, "{err}"),

            // Command and input errors
            Self::CommandFailed(program, status, output) => write!(
                f,
                "Command `{program}` failed with status `{status}` and output `{output}`"
            ),
            Self::CommandNotFound(command) => {
                write!(f, "Command does not exist: {command}")
            }
            Self::DurationParseError(d, u) => {
                write!(f, "Failed to parse duration `{d}` and `{u}`")
            }
            Self::NoQuery => f.write_str(FAIL_NO_QUERY_PROVIDED),
            Self::EmptySearchResult => f.write_str(EMPTY_SEARCH_RESULT),
            Self::EmptyVector(msg) => write!(f, "{FAIL_EMPTY_VECTOR} {msg}"),
            Self::IndexOutOfBounds { name, index } => {
                write!(f, "Index out of bounds for `{name}` at {index}")
            }
            Self::InvalidIP(ip) => write!(f, "Invalid ip {ip}"),
            Self::NotInRange(param, value, lower, upper) => {
                write!(
                    f,
                    "`{param}` should be between {lower} and {upper} but was {value}"
                )
            }

            // Missing resource errors
            Self::GuildOnly => f.write_str(GUILD_ONLY),
            Self::NoChannelId => f.write_str(NO_CHANNEL_ID),
            Self::NoDatabasePool => f.write_str(NO_DATABASE_POOL),
            Self::NoGuildCached => f.write_str(NO_GUILD_CACHED),
            Self::NoGuildId => f.write_str(NO_GUILD_ID),
            Self::NoGuildForChannelId(channel_id) => {
                write!(f, "No guild for channel id {channel_id}")
            }
            Self::NoGuildSettings => f.write_str(NO_GUILD_SETTINGS),
            Self::NoLogChannel => f.write_str("No log channel"),
            Self::NoMetadata => f.write_str(NO_METADATA),
            Self::NoTrackName => f.write_str(NO_TRACK_NAME),
            Self::NoTrackPlaying => f.write_str(FAIL_NOTHING_PLAYING),
            Self::NothingPlaying => f.write_str(FAIL_NOTHING_PLAYING),
            Self::NoSongbird => f.write_str(FAIL_NO_SONGBIRD),
            Self::InvalidTopGGToken => f.write_str(FAIL_INVALID_TOPGG_TOKEN),
            Self::NoVirusTotalApiKey => f.write_str(FAIL_NO_VIRUSTOTAL_API_KEY),
            Self::RoleNotFound(role_id) => write!(f, "{ROLE_NOT_FOUND} {role_id}"),
            Self::MissingEnvVar(var) => write!(f, "{MISSING_ENV_VAR} {var}"),
            Self::MissingUserPermissions(perm) => {
                let perm_str = perm
                    .map(|p| p.to_string())
                    .unwrap_or(COULD_NOT_FIND_PERMS.to_string());
                write!(f, "{FAIL_MISSING_USER_PERMISSIONS}: {perm_str}")
            }
            Self::MissingBotPermissions(perm) => {
                let perm_str = perm
                    .map(|p| p.to_string())
                    .unwrap_or(COULD_NOT_FIND_PERMS.to_string());
                write!(f, "{FAIL_MISSING_BOT_PERMISSIONS}: {perm_str}")
            }
            Self::LogChannelWarning(event_name, guild_id) => {
                write!(f, "No log channel set for {event_name} in {guild_id}")
            }
            Self::NoUserAutoplay => f.write_str(NO_USER_AUTOPLAY),

            // Operation failures
            Self::FailedResume => f.write_str(FAIL_RESUME),
            Self::FailedToInsert => f.write_str(FAIL_INSERT),
            Self::FailedToInsertGuildSettings => f.write_str(FAIL_INSERT_GUILD_SETTINGS),
            Self::FailedToSetChannelSize(name, id, size, err) => {
                write!(f, "{FAIL_TO_SET_CHANNEL_SIZE} {name}, {id}, {size}\n{err}")
            }
            Self::PlayListFail => f.write_str(FAIL_PLAYLIST_FETCH),
            Self::ParseTimeFail => f.write_str(FAIL_PARSE_TIME),
            Self::QueueEmpty => f.write_str(QUEUE_IS_EMPTY),
            Self::NotImplemented => f.write_str(FAIL_NOT_IMPLEMENTED),
            Self::UnimplementedEvent(channel, value) => {
                write!(f, "Unimplemented event {value} for channel {channel}")
            }

            // External service errors
            Self::AudioStream(err) => write!(f, "{err}"),
            Self::AudioStreamRustyYtdlMetadata => {
                f.write_str(FAIL_AUDIO_STREAM_RUSTY_YTDL_METADATA)
            }
            Self::AuxMetadataError(err) => write!(f, "{err}"),
            Self::Control(err) => write!(f, "{err}"),
            Self::RSpotify(err) => write!(f, "{err}"),
            Self::RSpotifyLockError(err) => write!(f, "rSpotify lock error: {err}"),
            Self::SpotifyAuth => f.write_str(SPOTIFY_AUTH_FAILED),
            Self::ResolveError(err) => write!(f, "{err}"),
            Self::VideoError(err) => write!(f, "{err}"),

            // Technical errors
            Self::Anyhow(err) => write!(f, "{err}"),
            #[cfg(feature = "crack-gpt")]
            Self::CrackGPT(err) => write!(f, "{err}"),
            Self::IO(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::PoisonError(err) => write!(f, "{err}"),
            Self::Poise(err) => write!(f, "{err}"),
            Self::Reqwest(err) => write!(f, "{err}"),
            Self::Serde(err) => write!(f, "{err}"),
            Self::Songbird(err) => write!(f, "{err}"),
            Self::Serenity(err) => write!(f, "{err}"),
            Self::SQLX(err) => write!(f, "{err}"),
            Self::TrackFail(err) => write!(f, "{err}"),
            Self::UrlParse(err) => write!(f, "{err}"),

            // General errors
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

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
            (Self::Serenity(l0), Self::Serenity(r0)) => format!("{l0:?}") == format!("{r0:?}"),

            // For all other variants, only compare the discriminant (variant type)
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

// From implementations for various error types

impl From<TrackResolveError> for CrackedError {
    fn from(err: TrackResolveError) -> Self {
        Self::ResolveError(err)
    }
}

impl From<ControlError> for CrackedError {
    fn from(err: ControlError) -> Self {
        Self::Control(err)
    }
}

impl From<anyhow::Error> for CrackedError {
    fn from(err: anyhow::Error) -> Self {
        Self::Anyhow(err)
    }
}

impl From<VideoError> for CrackedError {
    fn from(err: VideoError) -> Self {
        Self::VideoError(err)
    }
}

impl From<AudioStreamError> for CrackedError {
    fn from(err: AudioStreamError) -> Self {
        Self::AudioStream(err)
    }
}

impl From<CrackedError> for AudioStreamError {
    fn from(err: CrackedError) -> Self {
        AudioStreamError::Fail(Box::new(err))
    }
}

impl From<sqlx::Error> for CrackedError {
    fn from(err: sqlx::Error) -> Self {
        Self::SQLX(err)
    }
}

impl From<Error> for CrackedError {
    fn from(err: Error) -> Self {
        CrackedError::Poise(err)
    }
}

impl From<std::io::Error> for CrackedError {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

impl From<serde_json::Error> for CrackedError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err)
    }
}

impl From<SerenityError> for CrackedError {
    fn from(err: SerenityError) -> Self {
        Self::Serenity(err)
    }
}

impl From<CrackedError> for SerenityError {
    fn from(_err: CrackedError) -> Self {
        SerenityError::Io(std::io::Error::other("CrackedError"))
    }
}

impl From<reqwest::Error> for CrackedError {
    fn from(err: reqwest::Error) -> Self {
        Self::Reqwest(err)
    }
}

impl From<url::ParseError> for CrackedError {
    fn from(err: url::ParseError) -> Self {
        Self::UrlParse(err)
    }
}

impl From<RSpotifyClientError> for CrackedError {
    fn from(err: RSpotifyClientError) -> Self {
        CrackedError::RSpotify(err)
    }
}

impl From<Elapsed> for CrackedError {
    fn from(_: Elapsed) -> Self {
        CrackedError::Other(Cow::Borrowed("Timeout"))
    }
}

impl From<JoinError> for CrackedError {
    fn from(err: JoinError) -> Self {
        CrackedError::JoinChannelError(Box::new(err))
    }
}

impl From<AuxMetadataError> for CrackedError {
    fn from(err: AuxMetadataError) -> Self {
        CrackedError::AuxMetadataError(err)
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
/// pub use crack_types::errors::{verify, CrackedError};
///
/// let optional: Option<i32> = Some(42);
/// let result = verify(optional, CrackedError::NotImplemented)?;
/// assert_eq!(result, 42);
///
/// let bool_val = true;
/// let result = verify(bool_val, CrackedError::NotImplemented)?;
/// assert_eq!(result, true);
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
    fn context(self, ctx: &'static str) -> CrackedResult<T>;

    /// Maps any error type to CrackedError::Other with the given message
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
    use std::{error::Error, io::ErrorKind};

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
            "file not found",
        ));

        let with_context = result.context("Failed to read configuration");
        assert!(with_context.is_err());

        match with_context {
            Err(CrackedError::Other(msg)) => {
                assert!(msg.contains("Failed to read configuration"));
                assert!(msg.contains("file not found"));
            }
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
            }
            _ => panic!("Expected Other error variant"),
        }
    }
}
