"use client";

import React, { useState, FormEvent } from "react";
import { getWalletAddress } from "@/lib/api";

export default function WalletAddress() {
  const [emailAddress, setEmailAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState(false);

  const [fetchedAddress, setFetchedAddress] = useState<{
    address: string;
  } | null>(null);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setSuccessMessage(false);

    try {
      const data = await getWalletAddress({ email: emailAddress });
      setFetchedAddress(data);
      setSuccessMessage(true);
    } catch (error) {
      console.error("Error fetching wallet address:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-2xl shadow-md rounded-lg p-6 bg-gray-100 mb-20">
      <h2 className="text-2xl font-bold mb-2 text-gray-800 text-center">
        Get XION Wallet Address
      </h2>
      <p className="text-lg text-gray-400 mb-6 text-center">
        Enter your email address to get your XION wallet address.
      </p>

      <form className="flex flex-col justify-between gap-8" onSubmit={onSubmit}>
        <div>
          <div className="text-black font-bold mb-2">Email address:</div>
          <input
            type="text"
            value={emailAddress}
            onChange={(e) => setEmailAddress(e.target.value)}
            placeholder="Type in your registered email address"
            required
            className="w-full px-4 py-2 rounded-lg bg-gray-800 text-gray-400 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <div className="text-black font-bold mb-2">XION Wallet Address:</div>
          <div
            className="px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none w-96"
          >
            {fetchedAddress?.address || "Your wallet address"}
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
          {loading ? "Fetching..." : "Get Wallet Address"}
        </button>
      </form>

      {/* Success message */}
      {successMessage && (
        <div className="mt-6 p-4 text-green-600 bg-green-100 rounded-lg">
          <p className="text-center text-xl">
            Wallet address fetched successfully!
          </p>
        </div>
      )}
    </div>
  );
}
