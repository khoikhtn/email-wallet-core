'use client';

import React, { useState, FormEvent } from 'react';
import { useStore } from '../store/useStore';
import { sendToken, sendCW20, sendNFT } from '@/lib/api';

export default function Form() {
  const [amount, setAmount] = useState('');
  const [recipientAddress, setRecipientAddress] = useState('');
  const [contractAddress, setContractAddress] = useState('');
  const [tokenId, setTokenId] = useState('');
  const [loading, setLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState(false);
  const [selectedTab, setSelectedTab] = useState<'xion' | 'cw20' | 'nft'>('xion');

  const { email, appPassword } = useStore();

  const handleTabSwitch = (tab: 'xion' | 'cw20' | 'nft') => {
    setSelectedTab(tab);
    setAmount('');
    setRecipientAddress('');
    setContractAddress('');
    setTokenId('');
    setSuccessMessage(false);
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setSuccessMessage(false);

    try {
      if (selectedTab === 'xion') {
        await sendToken({ email, appPassword, recipient: recipientAddress, amount: parseFloat(amount) });
      } else if (selectedTab === 'cw20') {
        await sendCW20({ email, appPassword, recipient: recipientAddress, contractAddress, amount: parseFloat(amount) });
      } else if (selectedTab === 'nft') {
        await sendNFT({ email, appPassword, recipient: recipientAddress, contractAddress, tokenId });
      }

      setSuccessMessage(true);
    } catch (error) {
      console.error('Error: ', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-2xl shadow-md rounded-lg p-6 bg-gray-100 mb-20">
      <h2 className="text-2xl font-bold mb-2 text-gray-800 text-center">Send Assets</h2>
      <p className="text-lg text-gray-400 mb-6 text-justify">
      Choose the appropriate tab for the type of transfer you'd like to make, such as sending XION, CW20 tokens, or NFTs. Then, fill out the required fields on transaction details.
      </p>

      {/* Tabs */}
      <div className="flex space-x-4 mb-6 justify-center">
        <button
          onClick={() => handleTabSwitch('xion')}
          className={`px-4 py-2 rounded-lg ${selectedTab === 'xion' ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-800'}`}
        >
          Send XION
        </button>
        <button
          onClick={() => handleTabSwitch('cw20')}
          className={`px-4 py-2 rounded-lg ${selectedTab === 'cw20' ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-800'}`}
        >
          Send CW20
        </button>
        <button
          onClick={() => handleTabSwitch('nft')}
          className={`px-4 py-2 rounded-lg ${selectedTab === 'nft' ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-800'}`}
        >
          Send NFT
        </button>
      </div>

      {/* Form content based on selected tab */}
      <form className="flex flex-col justify-between h-56" onSubmit={onSubmit} >
      <div className='flex flex-col gap-3'>

        {selectedTab === 'cw20' && (
          <input
            type="text"
            value={contractAddress}
            onChange={(e) => setContractAddress(e.target.value)}
            placeholder="Contract Address"
            required
            className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        )}
        {selectedTab === 'nft' && (
          <>
            <input
              type="text"
              value={contractAddress}
              onChange={(e) => setContractAddress(e.target.value)}
              placeholder="Contract Address"
              required
              className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <input
              type="text"
              value={tokenId}
              onChange={(e) => setTokenId(e.target.value)}
              placeholder="Token ID"
              required
              className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </>
        )}
        <input
          type="text"
          value={recipientAddress}
          onChange={(e) => setRecipientAddress(e.target.value)}
          placeholder="Recipient Address"
          required
          className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        {selectedTab !== 'nft' && (
          <div className='flex justify-between items-center gap-4'>
            <input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="Amount"
              required
              className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <span className='text-black'>{selectedTab === 'xion' ? 'UXION' : 'TOKEN'}</span>
          </div>
        )}
          
        </div>
        <button
          type="submit"
          className={`w-full px-6 py-2 rounded-lg bg-beige text-black font-medium hover:bg-opacity-90 transition focus:outline-none focus:ring-2 focus:ring-beige focus:ring-offset-2 focus:ring-offset-black ${
            loading ? 'opacity-50 cursor-not-allowed' : ''
          }`}
          style={{ backgroundColor: '#f5c89c' }}
          disabled={loading}
        >
          {loading ? 'Sending...' : 'Send'}
        </button>
        </form>

      {/* Success message */}
      {successMessage && (
        <div className="mt-6 p-4 text-green-600 bg-green-100 rounded-lg">
          <p className="text-center text-xl">
            Transaction completed successfully! <br />
            For more information, please check your email.
          </p>
        </div>
      )}
    </div>
  );
}
