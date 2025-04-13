'use client';

import { getTransactionsHistory } from "@/lib/api";
import { useEffect, useState } from "react";
import { useAppContext } from "@/hooks/AppContext";

type Transaction = {
  sender: string;
  recipient: string;
  action: string;
  timestamp: string;
};

export default function TransactionsHistory() {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const { walletAddress } = useAppContext();

  useEffect(() => {
    if (!walletAddress) return;

    const fetchTransactions = async () => {
      try {
        const { transactions } = await getTransactionsHistory(walletAddress);
        setTransactions(transactions);
      } catch (error) {
        console.error("Error fetching transactions history:", error);
      }
    };

    fetchTransactions();
  }, [walletAddress]);

  return (
    <div className="w-full max-w-4xl shadow-md rounded-lg p-6 bg-gray-100 mb-20">
      <h2 className="text-2xl font-bold mb-10 text-gray-800 text-center">
        Transactions History
      </h2>

      <div className="overflow-x-auto shadow border border-gray-200 rounded-md">
        <table className="min-w-full divide-y divide-gray-200 bg-white">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-center text-black font-bold mb-2">
                Sender
              </th>
              <th className="px-6 py-3 text-center text-black font-bold mb-2">
                Recipient
              </th>
              <th className="px-6 py-3 text-center text-black font-bold mb-2">
                Action
              </th>
              <th className="px-6 py-3 text-center text-black font-bold mb-2">
                Timestamp
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {transactions.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-6 py-4 text-center text-sm text-black">
                  No transactions found.
                </td>
              </tr>
            ) : (
              transactions.map((tx, index) => (
                <tr key={index} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-xs text-center text-gray-800 break-all">{shortenAddress(tx.sender)}</td>
                  <td className="px-6 py-4 text-xs text-center text-gray-800 break-all">{shortenAddress(tx.recipient)}</td>
                  <td className="px-6 py-4 text-xs text-center text-blue-600 font-medium">{tx.action}</td>
                  <td className="px-6 py-4 text-xs text-center text-gray-600">
                    {new Date(tx.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const shortenAddress = (address: string) => {
  if (address.length <= 13) return address; // just in case it's short
  return `${address.slice(0, 8)}...${address.slice(-5)}`;
};
