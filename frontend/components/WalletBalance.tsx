"use client";

import React, { useState, FormEvent } from "react";
import { getWalletBalance } from "@/lib/api";

export default function WalletBalance() {
  const [walletAddress, setWalletAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState(false);

  const [fetchedBalance, setFetchedBalance] = useState<{
    cw20Balance: string;
    cw721Balance: string[];
  } | null>(null);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setSuccessMessage(false);
    try {
      const data = await getWalletBalance({ accountAddr: walletAddress });
      setFetchedBalance(data);
      setSuccessMessage(true);
    } catch (error) {
      console.error("Error fetching balance:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-2xl shadow-md rounded-lg p-6 bg-gray-100 mb-20">
      <h2 className="text-2xl font-bold mb-2 text-gray-800 text-center">
        Get Wallet Balance
      </h2>
      <p className="text-lg text-gray-400 mb-6 text-center">
        Enter XION wallet address to get balance
      </p>

      <form className="flex flex-col justify-between gap-8" onSubmit={onSubmit}>
        <div>
          <div className="text-black font-bold mb-2">Wallet address:</div>
          <input
            type="text"
            value={walletAddress}
            onChange={(e) => setWalletAddress(e.target.value)}
            placeholder="xion..."
            required
            className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <div className="text-black font-bold mb-2">Your assets:</div>

          <div className="text-black">CW20</div>
          <div className="flex gap-1 w-64 mb-4 items-center">
            <div
              className="w-32 px-4 py-2 mr-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {fetchedBalance?.cw20Balance || "Your balance"}
            </div>
            <div className="text-black">TOKEN</div>
          </div>

          <div className="text-black font-medium">CW721 IDs</div>
          <div className="w-64 px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600">
            {fetchedBalance?.cw721Balance?.join(", ") || "Your NFT IDs"}
          </div>
        </div>

        <button
          type="submit"
          className={`w-full px-6 py-2 rounded-lg bg-beige text-black font-medium hover:bg-opacity-90 transition focus:outline-none focus:ring-2 focus:ring-beige focus:ring-offset-2 focus:ring-offset-black ${
            loading ? "opacity-50 cursor-not-allowed" : ""
          }`}
          style={{ backgroundColor: "#f5c89c" }}
          disabled={loading}
        >
          {loading ? "Fetching..." : "Get Balance"}
        </button>
      </form>
      {/* Success message */}
      {successMessage && (
        <div className="mt-6 p-4 text-green-600 bg-green-100 rounded-lg">
          <p className="text-center text-xl">Balance fetched successfully!</p>
        </div>
      )}
    </div>
  );
}
