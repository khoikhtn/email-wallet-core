FROM node:20.18.1

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl

RUN mkdir /root/params
RUN curl https://email-wallet-trusted-setup-ceremony-pse-p0tion-production.s3.eu-central-1.amazonaws.com/circuits/emailwallet-account-creation/contributions/emailwallet-account-creation_00019.zkey --output /root/params/account_creation.zkey
RUN curl https://email-wallet-trusted-setup-ceremony-pse-p0tion-production.s3.eu-central-1.amazonaws.com/circuits/emailwallet-account-init/contributions/emailwallet-account-init_00007.zkey --output /root/params/account_init.zkey
RUN curl https://email-wallet-trusted-setup-ceremony-pse-p0tion-production.s3.eu-central-1.amazonaws.com/circuits/emailwallet-account-transport/contributions/emailwallet-account-transport_00005.zkey --output /root/params/account_transport.zkey
RUN curl https://email-wallet-trusted-setup-ceremony-pse-p0tion-production.s3.eu-central-1.amazonaws.com/circuits/emailwallet-claim/contributions/emailwallet-claim_00006.zkey --output /root/params/claim.zkey
RUN curl https://email-wallet-trusted-setup-ceremony-pse-p0tion-production.s3.eu-central-1.amazonaws.com/circuits/emailwallet-email-sender/contributions/emailwallet-email-sender_00006.zkey --output /root/params/email_sender.zkey

WORKDIR /code/email-wallet/packages/prover

RUN npm install -g snarkjs@latest
COPY packages/prover/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

COPY packages/prover .
RUN chmod +x circom_proofgen.sh
RUN mkdir -p build
RUN mv /root/params/* params

CMD [ "python3", "local.py" ]
