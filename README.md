# Internal PKI

This project aims to lay the foundation for an **internal certificate infrastructure** suitable for a small/medium-sized organization. Key points of the project:

- **Internal PKI** using OpenSSL toolkit for generating CAs, issuing and signing certificates; possible upgrade could be [Smallstep](https://smallstep.com/), open-source CA designed to be an online internal intermediate CA;
- **Password manager** for secure password and key storage;
- **TLS** for granting authenticity of internal servers and devices and securing the communication (integrity and confidentiality);


## Internal PKI

```
mkdir pki
cd pki
```

### 1. Create Root CA

```bash
mkdir -p rootCA/{private,certs,crl,newcerts}
touch rootCA/index.txt
echo 1000 > rootCA/serial
chmod 700 rootCA/private
```

Create the custom config file `rootca.cnf`.

Create Root CA private key encrypted with `-aes256`:

```bash
openssl genrsa -aes256 -out rootCA/private/rootCA.key.pem 4096
chmod 400 rootCA/private/rootCA.key.pem
```

Create Root CA self-signed certificate:

```bash
openssl req -config rootca.cnf -key rootCA/private/rootCA.key.pem -new -x509 -sha256 -days 3650 -extensions v3_ca -out rootCA/certs/rootCA.cert.pem
```

Verify the new certificate:

```bash
openssl x509 -in rootCA/certs/rootCA.cert.pem -noout -text
```

### 2. Create intermediate CAs for divisions (if any)

Change directory into `intermediateDivA`.

```bash
mkdir -p {private,certs,crl,newcerts}
touch index.txt
echo 1000 > serial
chmod 700 private
```

```bash
openssl genrsa -aes256 -out private/intermediate_A.key.pem 4096
chmod 400 private/intermediate_A.key.pem
```

Create the `intermediate-diva.cnf` inside the `intermediateDivA` folder.

```bash
openssl req -config intermediate-diva.cnf -new -sha256 -key private/intermediate_A.key.pem -out intermediate_A.csr.pem
```

```bash
cd ..
openssl ca -config rootca.cnf -extensions v3_intermediate_ca -days 1825 -notext -md sha256 -in intermediateDivA/intermediate_A.csr.pem -out intermediateDivA/certs/intermediate_A.cert.pem
```

Verify the intermediate cert chain, should return "OK":

```bash
openssl verify -CAfile rootCA/certs/rootCA.cert.pem intermediateDivA/certs/intermediate_A.cert.pem
```

Inspect the certificate's content:

```bash
openssl x509 -in intermediateDivA/certs/intermediate_A.cert.pem -noout -text
```


### 3. Issue certificates for devices and servers

- Create the intermediate CA's configuration file: `intermediate-diva.ca.cnf`;
- Issue the server certificate;
- Issue the client certificate;
- Create the certificate chain file;


## Secure password and key storage

- The machine where you perform the PKI steps or at least the drive should be offline and air-gapped, using encrypted drives to move certificate requests in and signed certificates out;
- Store the hard drives containing the CA private keys in a physical safe;
- Passphrases must be very strong and stored securely and separately from the key;

## TLS

The server will use:
- Server key `server.key.pem`
- Server fullchain certificate (server cert + intermediate cert) `server.chain.cert.pem`
- Fullchain CA (intermediate CA cert + root CA cert) `ca.cert.pem`

The client will use:
- Client key `client.key.pem`
- Client fullchain certificate (client cert + intermediate cert) `client.chain.cert.pem`
- Root CA `rootCA.cert.pem`


## Client

The client app is built to be very flexible and to be used in almost any system. This specific application needs it to run on an embedded system (ARM Cortex-A9), so its limited resources have been taken into account and some legacy versions of the protocols and algorithms have been used.

- Install dependencies: `sudo apt install zlib1g-dev libssl-dev`
- Compile client: `gcc -o client client.c -lssl -lcrypto -lz -Wall -Wextra`
- Run client: `./client 127.0.0.1 5060 . --compress`

## Server

- Compile server: `gcc -o server server.c -lssl -lcrypto`
- Run server: `SSL_CERT_FILE=./certs/localhost.chain.cert.pem SSL_KEY_FILE=./certs/localhost.key.pem SSL_CA_FILE=./certs/ca.cert.pem ./server`

## Node server

- `cd node-server`
- `sudo docker build -t node-server .`
- `sudo docker run --name node-server -p 5060:5060 -v "$(pwd)/received":/received -v "$(pwd)/certs":/certs:ro node-server`
- To run the dockerized app: `docker compose up --build`
