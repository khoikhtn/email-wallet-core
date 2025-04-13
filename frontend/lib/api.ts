const BASE_URL = "http://localhost:3000";

export const sendRequest = async <T, R>(endpoint: string, data: T): Promise<R> => {
  const url = `${BASE_URL}${endpoint}`;
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(data),
  }).then((res) => {
    if (!res.ok) throw new Error("Failed to send request");
    return res.json() as Promise<R>;
  });
};

export const sendContactEmail = async (data: { email: string; appPassword: string }): Promise<{ success: boolean }> => {
  return sendRequest("/send-email", data);
};

export const sendToken = async (data: { email: string; appPassword: string; recipient: string; amount: number }): Promise<{ success: boolean }> => {
  return sendRequest("/send-token", data);
};

export const sendCW20 = async (data: { email: string; appPassword: string; recipient: string; contractAddress: string; amount: number }): Promise<{ success: boolean }> => {
  return sendRequest("/send-cw20", data);
};

export const sendNFT = async (data: { email: string; appPassword: string; recipient: string; contractAddress: string; tokenId: string }): Promise<{ success: boolean }> => {
  return sendRequest("/send-nft", data);
};

export const getTransactions = async (): Promise<Array<{ id: string; type: string; amount: number; date: string }>> => {
  return fetch(`${BASE_URL}/get-transactions`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  }).then((res) => {
    if (!res.ok) throw new Error("Failed to get transactions");
    return res.json();
  });
};

export const getWalletBalance = async (data: { accountAddr: string }): Promise<{
  cw20Balance: string;
  cw721Balance: string[];
}> => {
  return fetch(`${BASE_URL}/get-wallet-balance`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(data),
  }).then((res) => {
    if (!res.ok) throw new Error("Failed to get wallet balance");
    return res.json();
  });
};


export const getWalletAddress = async (data: { email: string }): Promise<{ address: string }> => {
  return fetch(`${BASE_URL}/get-wallet-address-using-email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(data),
  }).then((res) => {
    if (!res.ok) throw new Error("Failed to get wallet address by email");
    return res.json();
  });
};

export const getTransactionsHistory = async (walletAddress: string): Promise<any> => {
  return fetch(`${BASE_URL}/transactions-history/${walletAddress}`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  }).then((res) => {
    if (!res.ok) throw new Error("Failed to get transactions history");
    return res.json();
  })
}

export const addTransactionHistory = async (data: {
  sender: string;
  recipient: string;
  action: string;
}): Promise<{ message: string; docId: string }> => {
  return fetch(`${BASE_URL}/transactions-history`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(data),
  }).then((res) => {
    if (!res.ok) throw new Error("Failed to add transaction");
    return res.json();
  });
};

