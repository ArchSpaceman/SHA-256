use std::convert::TryInto;

static H0: u32 = 0x6a09e667;
static H1: u32 = 0xbb67ae85;
static H2: u32 = 0x3c6ef372;
static H3: u32 = 0xa54ff53a;
static H4: u32 = 0x510e527f;
static H5: u32 = 0x9b05688c;
static H6: u32 = 0x1f83d9ab;
static H7: u32 = 0x5be0cd19;

static INITIAL_APPEND_INT: u8 = 128;

static K_VECTOR: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/*

 */
fn message_digest(chunk : &Vec<u8>) -> Result<[[u8;4];64],String>{
    
    let mut words_vector: [[u8;4];64] = [[0; 4]; 64];
    
    for i in 0 .. 16 {
        words_vector[i] = chunk[i*4 .. (i+1) * 4].try_into().expect("Couldn't break chunk into words");
    };

    for i in 0 .. 48 {
        let sigma_0 : u32 = ( u32::from_be_bytes(words_vector[i+1]).rotate_right(7))  
                              ^ ( u32::from_be_bytes(words_vector[i+1]).rotate_right(18)) 
                              ^ ( u32::from_be_bytes(words_vector[i+1]) >> 3);

        let sigma_1 : u32 = ( u32::from_be_bytes(words_vector[i+14]).rotate_right(17)) 
                              ^ ( u32::from_be_bytes(words_vector[i+14]).rotate_right(19))
                              ^ ( u32::from_be_bytes(words_vector[i+14]) >> 10);  

        words_vector[i+16] = u32::to_be_bytes( u32::from_be_bytes(words_vector[i])
                           + u32::from_be_bytes(words_vector[i+9]) 
                           + sigma_0 
                           + sigma_1);
    };
    Ok(words_vector)
}
/*
 This function compresses the digest of a message and returns a result of 8 Words
 */
fn compress_message(digest: &[[u8;4];64],h: Option<[u32;8]>) ->Result<[u32;8],String> {

    let mut compressed_words: [u32;8] = h.unwrap_or([ H0, H1, H2, H3, H4, H5, H6, H7 ]);

    let mut h_vec = h.unwrap_or([ H0, H1, H2, H3, H4, H5, H6, H7 ]);
    
    for i in 0..64 {


        let  majority: u32 = ( compressed_words[0] & compressed_words[1] ) 
                            ^ ( compressed_words[0] & compressed_words[2] ) 
                            ^ ( compressed_words[1] & compressed_words[2] );

        let  choice: u32 = ( compressed_words[4] & compressed_words[5] ) 
                            ^ ( (!compressed_words[4]) & compressed_words[6] );


        let  sigma_0: u32 = ( compressed_words[0].rotate_right(2) ) 
                            ^ ( compressed_words[0].rotate_right(13) ) 
                            ^ ( compressed_words[0].rotate_right(22) );

        let  sigma_1: u32 = ( compressed_words[4].rotate_right(6) ) 
                            ^ ( compressed_words[4].rotate_right(11) ) 
                            ^ ( compressed_words[4].rotate_right(25) );

        
        let temp_1: u32 = compressed_words[7] + sigma_1 + choice + K_VECTOR[i] + u32::from_be_bytes(digest[i]);

        let temp_2: u32 = sigma_0 + majority;

        compressed_words[7] = compressed_words[6];

        compressed_words[6] = compressed_words[5];

        compressed_words[5] = compressed_words[4];

        compressed_words[4] = compressed_words[3] + temp_1;

        compressed_words[3] = compressed_words[2];

        compressed_words[2] = compressed_words[1];

        compressed_words[1] = compressed_words[0];

        compressed_words[0] = temp_1 + temp_2;
    }
    
    h_vec[7] = h_vec[7] + compressed_words[7];

    h_vec[6] = h_vec[6] + compressed_words[6];

    h_vec[5] = h_vec[5] + compressed_words[5];

    h_vec[4] = h_vec[4] + compressed_words[4] ;

    h_vec[3] = h_vec[3] + compressed_words[3];

    h_vec[2] = h_vec[2] + compressed_words[2];

    h_vec[1] = h_vec[1] + compressed_words[1];

    h_vec[0] = h_vec[0] + compressed_words[0];

    Ok(h_vec)
}
pub fn hash_256(initial_string : String)-> Option<[u32; 8]>{

    let mut vectorized_string : Vec<u8> = initial_string.into_bytes();

    let initial_number_of_bytes : usize = vectorized_string.len();

    let initial_number_of_bits : usize = initial_number_of_bytes * 8;

    vectorized_string.push(INITIAL_APPEND_INT);

    let expected_length_in_bytes: u32 = ( initial_number_of_bytes as u32 + 8 ).div_ceil(64) * 64;

    let mut padding_zero_vec: Vec<u8> = vec![0; expected_length_in_bytes as usize - vectorized_string.len() - 8];

    let  intial_string_len_array: [u8; 8] = initial_number_of_bits.to_be_bytes();

    vectorized_string.append(&mut padding_zero_vec);
    vectorized_string.extend_from_slice(&intial_string_len_array);

    let number_of_chunks: u32 = expected_length_in_bytes / 64;


    let mut chunks_vec: Vec<Vec<u8>> = vec![];

    for i in 0..number_of_chunks {
        let mut chunk: Vec<u8> = vec![];
        chunk.extend_from_slice(&vectorized_string[(i * 64) as usize..((i + 1) * 64) as usize]);
        chunks_vec.push(chunk);
    }
;

    let mut compressed_message: [u32; 8] = [0;8];

    for i in  0 .. chunks_vec.len(){
        let digest = message_digest(&chunks_vec[i]).expect("Couldn't digest message");
        if i == 0{
            compressed_message = compress_message(&digest,None).expect("Couldn't compress message");
        }
        else {
            compressed_message = compress_message(&digest,Some(compressed_message)).expect("Couldn't compress message");
        }
    }
    Some(compressed_message)
}
