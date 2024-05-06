# Kerberos + Diffie Hellman Data Encryption

This project combines two cryptographic concepts, Kerberos and Diffie-Hellman, to create a custom solution for tokenizing/encrypting data before transmitting it over the internet. The aim is to ensure data security with dynamically generated keys unique to each request. Below is an explanation of the logic behind the implementation.

## Executing code

### Tokenizer-server

<pre>
  cd tokenizer-client
  cargo run
</pre>

### Tokenizer-client

<pre>
  cd tokenizer-client
  cargo run
</pre>

### Outputs
### Tokenizer-server
<pre>
  a: 900204063
  public_a: 151366720
</pre>

### Tokenizer-client
<pre>
  b: 167872925
  public_b: 543888577
  Chave secreta de BOB 820885131
  Resposta do /finish: 200
  Corpo da Resposta: {"shared_secret_alice":820885131}
</pre>

