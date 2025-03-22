# crack-types

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.85.0%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/crack-types.svg)](https://crates.io/crates/crack-types)

Common types and utilities for [Crack Tunes](https://cracktun.es/) - a Discord music bot.

## Overview

`crack-types` is a Rust library that provides common types, utilities, and error handling for the Crack Tunes Discord music bot ecosystem. It abstracts away much of the complexity involved in working with Discord's API, music streaming services, and audio management.

## Features

- **Discord Integration**: Types and utilities for interacting with Discord via the Serenity library
- **Music Service Integration**: Support for Spotify, YouTube, and other music services
- **HTTP Utilities**: Functions for URL parsing and handling
- **Error Handling**: Comprehensive error system with detailed error types
- **Message Management**: Structured message handling for Discord interactions
- **Type Abstractions**: Common types to simplify working with the bot's ecosystem

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
crack-types = "0.4.0"
```

Or use cargo:

```bash
cargo add crack-types
```

## Usage

```rust
use crack_types::{CrackedResult, QueryType, SpotifyTrackTrait};
use crack_types::http::{parse_url, resolve_final_url};

// Parse and resolve URLs
async fn get_final_url(url_str: &str) -> CrackedResult<String> {
    let client = reqwest::Client::new();
    let final_url = resolve_final_url(client, url_str).await?;
    Ok(final_url)
}

// Work with music queries
fn create_music_query(input: &str) -> QueryType {
    // Automatically determines if input is a URL or keywords
    QueryType::from_str(input).unwrap_or_default()
}
```

## Features

The library provides optional features that can be enabled in your `Cargo.toml`:

- `crack-tracing`: Enables tracing for debugging and logging (enabled by default)
- `crack-gpt`: Enables GPT-related functionality

```toml
[dependencies]
crack-types = { version = "0.4.0", features = ["crack-gpt"] }
```

## Key Components

### Error Handling

The library provides a comprehensive error handling system through the `CrackedError` enum, which covers various error scenarios when working with Discord, audio streaming, and music services.

### QueryType

The `QueryType` enum provides a unified way to handle different types of music queries:

- Keywords/search terms
- Direct video links
- Spotify tracks
- Playlist links
- File attachments
- YouTube searches

### HTTP Utilities

Simple functions for working with URLs:

- `parse_url`: Parse a URL string into a URL object
- `resolve_final_url`: Get the final URL after following all redirects

## Requirements

- Rust 1.85.0 or higher

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Links

- [Crack Tunes Website](https://cracktun.es/)
- [GitHub Repository](https://github.com/cycle-five/crack-types)
