#![allow(warnings)]
use std::fs;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};
use tfhe::integer::{gen_keys_radix, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use bincode;
use tfhe::{ClientKey, ConfigBuilder, FheUint, FheUint16, FheUint16Id, FheUint32, FheUint32Id, FheUint8, FheUint8Id, generate_keys, set_server_key};
use tfhe::prelude::{FheDecrypt, FheEncrypt};

fn main() -> Result<(), Box<dyn std::error::Error>>{
    //println!("");
    //my_key_gen()?;

    //println!("reading client key...");
    let mut byte_vec = fs::read("client_key.bin")?;

    //println!("deserializing client key...");
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;


    //let enc_data = encryptStr("kapple", &ck);
    let s = "cat";
    let enc_ascii = encryptascii(s.clone(), &ck);
    println!("encrypting {:?} string...", s.clone());

    /*
    println!("serializing encrypted string...");
    let mut serialized_enc_str = Vec::new();
    for i in enc_data.clone() {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("encrypted_str.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");
    */
    println!("serializing encrypted string...");
    let mut serialized_enc_str = Vec::new();
    for i in enc_ascii.clone() {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("encrypted_ascii.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");

    //println!("deserializing intercepted_payload.bin...");
    //let file = fs::read("encrypted_str.bin")?;
    //let enc_str = deserialize_str(&file)?;

    //let s = decryptStr(enc_str.clone(), &ck);
    //println!("the decrypted str is {}",s);

    Ok(())

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

    //println!("Average elapsed time: {:?}", average_elapsed);
    v
}

pub fn encryptStr(content: &str, ck: &ClientKey) -> Vec<FheUint<FheUint16Id>> {
    let mut v:Vec<u8> = content.chars().map(|c| match c {
        'a' => 1,
        'p' => 2,
        'l' => 3,
        'e' => 4,
        _ => 5,
    }).collect();
    println!("encryptedstr is{:?}:", v);

    let mut r = vec![];
    for i in v{
        r.push(FheUint16::encrypt(i, ck));
    }
    r

    /*
    let fhe_bytes: Vec<FheUint8> = content
        .bytes()
        .map(|b| FheUint8::encrypt(b, &ck))
        .collect();
    fhe_bytes
     */
}

fn decode_char(code: u32) -> char {
    match code {
        1 => 'a',
        2 => 'b',
        _ => 'X',
    }
}

fn decode_string(codes: Vec<u32>) -> String {
    codes.into_iter().map(decode_char).collect()
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

pub fn decryptStr(content: Vec<FheUint<FheUint16Id>>, ck: &ClientKey) -> String {
    let mut v = vec![];
    for byte in content {
        v.push(byte.decrypt(&ck));
    }
    println!("{:?}", v);
    decode_string(v)
    //String::from_utf8(v).unwrap()

}


/*
fn main() -> Result<(), Box<dyn std::error::Error>>{
    my_key_gen()?;

    println!("reading client key...");
    let mut byte_vec = fs::read("client_key.bin")?;
    println!("deserializing client key...");
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;
    println!("encrypting string...");
    let enc_data = encryptStr("my linux", &ck);
    println!("serializing ciphertext...");
    let mut serialized_enc_str = Vec::new();
    for i in enc_data {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("encrypted_str.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");


    let mut enc_vec = fs::read("encrypted_str.bin")?;
    /*
    let mut to_des_data: Option<Cursor<Vec<u8>> >= Some(Cursor::new(serialized_enc_str));
    let mut v = vec ! [];
    loop {
        match to_des_data {
            Some(_) => v.push(bincode::deserialize_from( &mut to_des_data.clone().unwrap()) ? ),
            None => break,
        }
    }
    */

    let mut to_des_data = Cursor::new(serialized_enc_str);
    let mut v = vec ! [];
    loop{
        v.push(bincode::deserialize_from( & mut to_des_data) ? );
    }
    let output = decryptStr(v, & ck );
    println ! ("the output is {:?}", output);


    Ok(())

}

pub fn encryptStr(content: &str, ck: &RadixClientKey) -> Vec<RadixCiphertext> {
    let mut v = vec![];
    for byte in content.bytes() {
        v.push(ck.encrypt(byte));
    }
    v
}


fn deserialize_ck(serialized_data: &[u8]) -> Result<RadixClientKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let ck: RadixClientKey= bincode::deserialize_from(&mut to_des_data)?;
    Ok(ck)
}

fn my_key_gen() -> Result<(), Box<dyn std::error::Error>> {
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);
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

    println!("finished serialization");
    Ok(())


}

pub fn decryptStr(content: Vec<RadixCiphertext>, ck: &RadixClientKey) -> String {
    let mut v = vec![];
    for byte in content {
        v.push(ck.decrypt(&byte));
    }
    String::from_utf8(v).unwrap()

}
 */
