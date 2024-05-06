use warp::Filter;
use warp::{http::StatusCode, reply::json};
use serde::{Deserialize, Serialize};
use openssl::symm::{encrypt,decrypt, Cipher};
use openssl::rand::rand_bytes;
use std::sync::Mutex;
use std::collections::HashMap;
use lazy_static::lazy_static;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use std::ops::Rem;

struct SessionData {
    a: u64, // ou o tipo de dado apropriado
    n: u64, // ou o tipo de dado apropriado
}


#[derive(Deserialize)]
struct Request {
    id_sessao: String,
    cliente_id: String,
}

#[derive(Serialize)]
struct ResponseM1 {
    public_a: u64,
    n: u64, 
    g: u64, 
    chave_x1: Vec<u8>,
}

#[derive(Serialize,Deserialize)]
struct ResponseM2 {
    id_sessao: String,
    chave_x1: Vec<u8>, // Simplificado para o exemplo
}

// Estrutura para C3
#[derive(Deserialize)]
struct C3Content {
    current_date: u128,
    public_b: u64,
}

lazy_static! {
    static ref CLIENT_KEYS: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
    static ref SESSION_DATA: Mutex<HashMap<String,SessionData>> = Mutex::new(HashMap::new());
}

#[tokio::main]
async fn main() {
    let start_route = warp::post()
        .and(warp::path("start"))
        .and(warp::body::json())
        .map(|req: Request| {
            //let chave_cliente = generate_random_aes_key();
            let chave_cliente: [u8; 32]  = [64, 197, 64, 115, 243, 12, 99, 0, 251, 250, 208, 100, 141, 253, 234, 207, 170, 233, 35, 217, 18, 69, 171, 104, 221, 230, 83, 95, 44, 236, 31, 17];

            let mut rng = rand::thread_rng();

            let n = generate_large_prime();
            let g = generate_large_prime();

            let a = rng.gen_range(1..n);
            let public_a = modpow(g, a, n); 

            println!("a: {}",a);
            println!("public_a: {}",public_a);

            let chave_x1 = generate_random_aes_key();
            let chave_x2 = generate_random_aes_key();

            CLIENT_KEYS.lock().unwrap().insert(req.id_sessao.clone(),chave_x2.clone());

            let response_m1 = ResponseM1 { public_a, chave_x1: chave_x1.clone(), n , g };
            let response_m2 = ResponseM2 { id_sessao: req.id_sessao.clone(), chave_x1: chave_x1 };

            let response_m1_string = serde_json::to_string(&response_m1).unwrap();
            let response_m1_encrypted = encrypt_aes(&chave_cliente, &response_m1_string.into_bytes()).unwrap();

            let response_m2_string = serde_json::to_string(&response_m2).unwrap();
            let response_m2_encrypted = encrypt_aes(&chave_x2, &response_m2_string.into_bytes()).unwrap();

            SESSION_DATA.lock().unwrap().insert(req.id_sessao.clone(),SessionData { a, n });

            let final_response = serde_json::json!({
                "c1": response_m1_encrypted,
                "c2": response_m2_encrypted
            });

            warp::reply::json(&final_response)
        });

    let finish_route = warp::post()
        .and(warp::path("finish"))
        .and(warp::path::param())
        .and(warp::body::json())
        .map(|id_sessao: String, body: serde_json::Value| {
            let c3_encrypted: Vec<u8> = serde_json::from_value(body["c3"].clone()).unwrap();
            let c2_encrypted: Vec<u8> = serde_json::from_value(body["c2"].clone()).unwrap();

            let chave_sessao = CLIENT_KEYS.lock().unwrap()
                .get(&id_sessao)
                .cloned()
                .expect("Chave de sessão não encontrada");

            let c2_decrypted = decrypt_aes(&chave_sessao, &c2_encrypted).unwrap();
            let response_m2: ResponseM2 = serde_json::from_slice(&c2_decrypted).unwrap();
            
            let c3_decrypted = decrypt_aes(&response_m2.chave_x1, &c3_encrypted).unwrap();
            let c3_content: C3Content = serde_json::from_slice(&c3_decrypted).unwrap();

            if is_current_date_within_5_minutes(c3_content.current_date) {
                let public_b = c3_content.public_b;
                let data = SESSION_DATA.lock().unwrap();
                if let Some(session_data) = data.get(&id_sessao) {
                    let shared_secret_alice = modpow(public_b,  session_data.a, session_data.n);
                    warp::reply::json(&serde_json::json!({"shared_secret_alice": shared_secret_alice}))

                }else{
                    //let shared_secret_alice = modpow(public_b, a, p);
                    warp::reply::json(&serde_json::json!({"primo": public_b}))
                }
                
            } else {
                let error_message = serde_json::json!({ "error": "Tempo expirado" });
                warp::reply::json(&error_message)
            }
        });

    let routes = start_route.or(finish_route);


    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

fn generate_large_prime() -> u64 {

    let numbers: [u64; 200]= [ 1000000007,
     1000000009,
     1000000021,
     1000000033,
     1000000087,
     1000000093,
     1000000097,
     1000000103,
     1000000123,
     1000000181,
     1000000207,
     1000000223,
     1000000241,
     1000000271,
     1000000289,
     1000000297,
     1000000321,
     1000000349,
     1000000363,
     1000000403,
     1000000409,
     1000000411,
     1000000427,
     1000000433,
     1000000439,
     1000000447,
     1000000453,
     1000000459,
     1000000483,
     1000000513,
     1000000531,
     1000000579,
     1000000607,
     1000000613,
     1000000637,
     1000000663,
     1000000711,
     1000000753,
     1000000787,
     1000000801,
     1000000829,
     1000000861,
     1000000871,
     1000000891,
     1000000901,
     1000000919,
     1000000931,
     1000000933,
     1000000993,
     1000001011,
     1000001021,
     1000001053,
     1000001087,
     1000001099,
     1000001137,
     1000001161,
     1000001203,
     1000001213,
     1000001237,
     1000001263,
     1000001269,
     1000001273,
     1000001279,
     1000001311,
     1000001329,
     1000001333,
     1000001351,
     1000001371,
     1000001393,
     1000001413,
     1000001447,
     1000001449,
     1000001491,
     1000001501,
     1000001531,
     1000001537,
     1000001539,
     1000001581,
     1000001617,
     1000001621,
     1000001633,
     1000001647,
     1000001663,
     1000001677,
     1000001699,
     1000001759,
     1000001773,
     1000001789,
     1000001791,
     1000001801,
     1000001803,
     1000001819,
     1000001857,
     1000001887,
     1000001917,
     1000001927,
     1000001957,
     1000001963,
     1000001969,
     1000002043,
     1000002089,
     1000002103,
     1000002139,
     1000002149,
     1000002161,
     1000002173,
     1000002187,
     1000002193,
     1000002233,
     1000002239,
     1000002277,
     1000002307,
     1000002359,
     1000002361,
     1000002431,
     1000002449,
     1000002457,
     1000002499,
     1000002571,
     1000002581,
     1000002607,
     1000002631,
     1000002637,
     1000002649,
     1000002667,
     1000002727,
     1000002791,
     1000002803,
     1000002821,
     1000002823,
     1000002827,
     1000002907,
     1000002937,
     1000002989,
     1000003009,
     1000003013,
     1000003051,
     1000003057,
     1000003097,
     1000003111,
     1000003133,
     1000003153,
     1000003157,
     1000003163,
     1000003211,
     1000003241,
     1000003247,
     1000003253,
     1000003267,
     1000003271,
     1000003273,
     1000003283,
     1000003309,
     1000003337,
     1000003351,
     1000003357,
     1000003373,
     1000003379,
     1000003397,
     1000003469,
     1000003471,
     1000003513,
     1000003519,
     1000003559,
     1000003577,
     1000003579,
     1000003601,
     1000003621,
     1000003643,
     1000003651,
     1000003663,
     1000003679,
     1000003709,
     1000003747,
     1000003751,
     1000003769,
     1000003777,
     1000003787,
     1000003793,
     1000003843,
     1000003853,
     1000003871,
     1000003889,
     1000003891,
     1000003909,
     1000003919,
     1000003931,
     1000003951,
     1000003957,
     1000003967,
     1000003987,
     1000003999,
     1000004023,
     1000004059,
     1000004099,
     1000004119,
     1000004123,
     1000004207,
     1000004233,
     1000004249];

     let mut rng = rand::thread_rng(); // Cria um gerador de números aleatórios
     let indice_aleatorio = rng.gen_range(0..numbers.len()); // Gera um índice aleatório
     let numero_aleatorio = numbers[indice_aleatorio]; // Acessa o número no array

     numero_aleatorio 
}

fn generate_random_aes_key() -> Vec<u8> {
    let mut key = [0u8; 32]; // 256 bits
    rand_bytes(&mut key).unwrap();
    key.to_vec()
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

fn is_current_date_within_5_minutes(date_ref: u128) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    date_ref <= now  && now - date_ref < 30000 // ms = 5 minutos
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

