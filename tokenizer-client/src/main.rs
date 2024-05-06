use reqwest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use openssl::symm::{encrypt, decrypt, Cipher};
use openssl::rand::rand_bytes;
use rand::Rng; // Importe Rng para gerar números aleatórios
use std::ops::Rem;

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct ResponseC1 {
    public_a: u64,
    n: u64, 
    g: u64, 
    chave_x1: Vec<u8>,
}

#[tokio::main]
async fn main() {
    // Gerar ID de sessão aleatório
    let id_sessao = Uuid::new_v4().to_string();

    // Dados da requisição
    let cliente_id = "cliente_exemplo";
    let client = reqwest::Client::new();
    let res = client.post("http://localhost:3030/start")
        .json(&serde_json::json!({
            "id_sessao": id_sessao,
            "cliente_id": cliente_id,
        }))
        .send()
        .await
        .unwrap();

    if res.status().is_success() {
        let body = res.json::<serde_json::Value>().await.unwrap();
        let chave_aes_cliente: [u8; 32]  = [64, 197, 64, 115, 243, 12, 99, 0, 251, 250, 208, 100, 141, 253, 234, 207, 170, 233, 35, 217, 18, 69, 171, 104, 221, 230, 83, 95, 44, 236, 31, 17];

        let c1_encrypted: Vec<u8> = serde_json::from_value(body["c1"].clone()).unwrap();
        let c1_decrypted = decrypt_aes(&chave_aes_cliente, &c1_encrypted).unwrap();

        let c1: ResponseC1 = serde_json::from_slice(&c1_decrypted).unwrap();        
        let c2: Vec<u8> = serde_json::from_value(body["c2"].clone()).unwrap();

        let n = c1.n;
        let g = c1.g;

        let mut rng = rand::thread_rng(); // Cria um gerador de números aleatórios
        let b = rng.gen_range(1..n);

        println!("b: {}",b);


        let public_b = modpow(g, b, n);
        println!("public_b: {}",public_b);

        let public_a = c1.public_a;
        let shared_secret_bob = modpow(public_a, b, n);
        println!("Chave secreta de BOB {}",shared_secret_bob);

        // Gerar resposta M3
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let c3 = serde_json::json!({
            "current_date": now,
            "public_b": public_b,
        });

        let c3_encrypted = encrypt_aes(&c1.chave_x1, &c3.to_string().into_bytes()).unwrap();

        let final_response = serde_json::json!({
            "id_sessao": id_sessao,
            "c3": c3_encrypted,
            "c2": c2
        });

        let mut url = String::from("http://localhost:3030/finish/");
        url.push_str(&id_sessao);

        // Enviar M3 para o endpoint /finish
        let finish_res = client.post(url)
            .json(&final_response)
            .send()
            .await
            .unwrap();

        println!("Resposta do /finish: {:?}", finish_res.status());
        let body = finish_res.text().await.unwrap();
        println!("Corpo da Resposta: {}", body);

    } else {
        println!("Erro na requisição: {:?}", res.status());
    }
}

fn encrypt_aes(key: &[u8], data: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_256_cbc();
    let mut iv = [0u8; 16];
    rand_bytes(&mut iv)?;
    let encrypted_data = encrypt(cipher, key, Some(&iv), data)?;

    // Combine IV and encrypted data
    let mut result = iv.to_vec();
    result.extend_from_slice(&encrypted_data);
    Ok(result)
}

fn decrypt_aes(key: &[u8], data: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_256_cbc();
    let iv = &data[0..16]; // IV é tipicamente os primeiros 16 bytes
    let encrypted_data = &data[16..];

    decrypt(cipher, key, Some(iv), encrypted_data)
}


// Função para calcular (base^exp) % modulus para u64
fn modpow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1;
    base = base.rem(modulus);
    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base % modulus;
        }
        exp = exp >> 1;
        base = base * base % modulus;
    }
    result
}