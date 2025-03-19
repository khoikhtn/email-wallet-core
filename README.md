# Xion Email Wallet

This project is build on top of [Email Wallet](https://github.com/zkemail/email-wallet).

## Backend

To run the backend server for proof verification, follow the steps below

### Installation

Clone repository

```bash
git clone https://github.com/hduoc2003/xion-email-wallet
cd xion-email-wallet
```

Before running the following steps, you need to install `cargo`, `yarn` and `docker`.

#### Create `.env` file

First, create a `.env` file in `packages/relayer` and update it with the following:

```ini
CHAIN_SDK_PROXY_SERVER=http://localhost:3000
PRIVATE_KEY=0x123456                      # Private key for Relayer's account.

# IMAP + SMTP (Settings will be provided by your email provider)
IMAP_DOMAIN_NAME=imap.gmail.com
IMAP_PORT=993
AUTH_TYPE=password
SMTP_DOMAIN_NAME=smtp.gmail.com
LOGIN_ID=example@gmail.com                  # IMAP login id - usually your email address.
LOGIN_PASSWORD=""         # IMAP password - usually your email password.

PROVER_LOCATION=local         # Keep this local for running the prover locally.
PROVER_ADDRESS="http://0.0.0.0:8080"

DATABASE_URL="postgres://emailwallet:password@localhost:5432/emailwallet"
RELAYER_EMAIL_ADDR=emailrelayer2003@gmail.com
RELAYER_HOSTNAME="gmail.com"
WEB_SERVER_ADDRESS="127.0.0.1:4500"
CIRCUITS_DIR_PATH=../circuits  #Path to email-wallet/packages/circuits
INPUT_FILES_DIR_PATH=/home/xion-email-wallet/packages/relayer/input_files  #Absolute path to email-wallet/packages/relayer/input_files
EMAIL_TEMPLATES_PATH=./eml_templates  #Path to email templates

JSON_LOGGER=false
```

#### Run prover and database

```bash
docker compose up -d
```

#### Run the relayer

```bash
yarn
cd packages/relayer
cargo run -- setup
cargo run
```

## Frontend

To run frontend application, do these steps below

### Navigate to the frontend Folder

Use the following command to move into the frontend directory:

```bash
cd frontend
```

### Install dependencies

Install all required packages by running:

```bash
npm i
```

### Start the Frontend Application

Launch the development server with

```bash
npm run dev
```
