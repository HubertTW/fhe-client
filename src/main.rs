#![allow(warnings)]
use std::{env, fs};
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::{BufReader, Cursor, Read, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};
use tfhe::integer::{gen_keys_radix, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use bincode;
use tfhe::{ClientKey, ConfigBuilder, FheUint, FheUint16, FheUint16Id, FheUint32, FheUint32Id, FheUint8, FheUint8Id, generate_keys, set_server_key};
use tfhe::prelude::{FheDecrypt, FheEncrypt};

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let args: Vec<String> = env::args().collect();
    //my_key_gen()?;

    //println!("reading client key...");
    let mut byte_vec = fs::read("client_key.bin")?;

    //println!("deserializing client key...");
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;


    let s = args[1].as_str();

    let space_indices: Vec<usize> = s
        .char_indices()
        .filter(|(_, c)| *c == ' ')
        .map(|(i, _)| i)
        .collect();

    println!("all the blankline index: {:?}", space_indices);

    let enc_ascii = encryptascii(s.clone(), &ck);
    println!("encrypting {:?} string...", s.clone());

    let enc_zero = FheUint16::encrypt(0u8, &ck);
    let enc_one = FheUint16::encrypt(1u8, &ck);

    //encryptPosition(s.clone(), &enc_zero, &enc_one).expect("serialization string wrong");
    //encryptLastPosition(s.clone(), &enc_zero, &enc_one).expect("serialization last char wrong");

    println!("serializing encrypted string...");
    let mut serialized_enc_str = Vec::new();
    for i in enc_ascii.clone() {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("encrypted_ascii.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");

    let file_path = "space_indices.txt";
    save_to_file(&space_indices, file_path);

    let loaded_indices = load_from_file(file_path);

    println!("Original indices: {:?}", space_indices);
    println!("Loaded indices: {:?}", loaded_indices);

    Ok(())

}


fn save_to_file(indices: &[usize], file_path: &str) {
    if let Ok(mut file) = File::create(file_path) {
        for index in indices {
            let _ = writeln!(file, "{}", index);
        }
    }
}


fn load_from_file(file_path: &str) -> Vec<usize> {
    if let Ok(file) = File::open(file_path) {
        let reader = BufReader::new(file);
        let mut indices = Vec::new();

        for line in reader.lines() {

            if let Ok(line) = line {

                if let Ok(value) = line.parse::<usize>() {
                    indices.push(value);
                }
            }
        }
        indices
    } else {
        Vec::new()
    }
}



pub fn encryptascii(content: &str, ck: &ClientKey) -> Vec<FheUint<FheUint16Id>>{
    let mut v = vec![];

    let measurements = 100;
    let mut elapsed_times: Vec<Duration> = Vec::new();

    for byte in content.bytes() {
        //let encode_char = byte - 97 + 0*2;
        v.push(FheUint16::encrypt(byte, ck));
    }

    for _ in 0..measurements {

        let start = Instant::now();

        for byte in content.bytes() {
            //let encode_char = byte - 97 + 0*2;
            FheUint16::encrypt(byte, ck);
        }

        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);

        //println!("Elapsed time: {:?}", elapsed);
    }

    // 計算平均經過時間
    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);
    println!("Average elapsed time: {:?}", average_elapsed);

    v
}





fn deserialize_ck(serialized_data: &[u8]) -> Result<ClientKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let ck: ClientKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(ck)
}

fn my_key_gen() -> Result<(), Box<dyn std::error::Error>> {
    //let config = ConfigBuilder::default().build();
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            None,
        )
        .build();
    let ( client_key, server_key) = generate_keys(config);
    //set_server_key(server_key.clone());

    let mut serialized_client_key = Vec::new();
    bincode::serialize_into(&mut serialized_client_key, &client_key)?;
    let mut file_ck = File::create("client_key.bin")?;
    let box_ck = serialized_client_key.into_boxed_slice();
    file_ck.write_all(box_ck.deref())?;

    let mut serialized_server_key = Vec::new();
    bincode::serialize_into(&mut serialized_server_key, &server_key)?;
    let mut file_sk = File::create("server_key.bin")?;
    let box_sk = serialized_server_key.into_boxed_slice();
    file_sk.write_all(box_sk.deref())?;

    println!("finished ck/sk serialization");
    Ok(())


}
fn deserialize_str(
    serialized_data: &[u8],
    content_size: u8
) -> Result<Vec<FheUint<FheUint16Id>>, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let mut v: Vec<FheUint<FheUint16Id>> = vec![];
    for _ in 0..content_size {
        // length of received string
        v.push(bincode::deserialize_from(&mut to_des_data)?);
    }
    Ok(v)
}

