# Crack-Types Development Guide

## Build Commands
- Build: `cargo build`
- Test all: `cargo test`
- Test single: `cargo test test_name`
- Lint: `cargo clippy -- -D warnings -W clippy::pedantic`
- Format: `cargo fmt`
- Check format: `cargo fmt -- --check`
- Documentation: `cargo doc --open`
- Run example: `cargo run --example errors`

## Code Style Guidelines
- Use Rust 2021 edition (requires Rust 1.88+)
- Follow Rust standard naming conventions (snake_case for functions/variables, CamelCase for types)
- Use thiserror for error definitions in error.rs
- Document all public items with doc comments
- Implement comprehensive error handling with CrackedError enum
- Use the Result<T, CrackedError> pattern for fallible functions
- Organize code into modules with clear separation of concerns
- Use feature flags for optional functionality
- Co-locate tests with implementation code
- Use standard Rust formatting (rustfmt)
- Follow clippy recommendations for idiomatic Rust
- Use anyhow::Context for error context when appropriate
- Prefer explicit imports over glob imports