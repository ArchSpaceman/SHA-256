
# A basic Implementation of Sha-256 Hashing algorithm in Rust

This crate is used to generate a sha-256 hash given a string, simply bring the crate into scope and use the function hash_256 that takes a String as an input. \
The return type of the function is a Result< [u32,8] , String>


## Usage/Examples

```rust
pub mod spacesha256;

let compressed_message = spacesha256::hash_256(String::from("Hello, World!")).expect("Failed to hash");
    
println!("{:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}", compressed_message[0],compressed_message[1],compressed_message[2],compressed_message[3],compressed_message[4],compressed_message[5],compressed_message[6],compressed_message[7]);
```


## Notes
The bitwise operations in SHA-256 algorithm might result in an overflow , however Rust's compiler panics on overflow in Debug mode. So I've appended overflow-checks = false to Cargo.toml . A possible improvment to make is to handle possible overflows during hashing.
