pub mod spacesha256;


fn main() {
    let initial_string = String::from("Hello, World!");

    let compressed_message = spacesha256::hash_256(initial_string).expect("Failed to hash");
    
    println!("{:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}", compressed_message[0],compressed_message[1],compressed_message[2],compressed_message[3],compressed_message[4],compressed_message[5],compressed_message[6],compressed_message[7]);

}

