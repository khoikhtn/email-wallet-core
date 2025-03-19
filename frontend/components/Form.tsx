'use client';

import React, { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation'; // Import useRouter from next/router
import { getWalletAddress, sendContactEmail } from '../lib/api';
import { useStore } from '../store/useStore';

export default function Form() {
  const [sender, setSender] = useState('');
  const [appPassword, setAppPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState(false);
  const [walletAddress, setWalletAddress] = useState('');

  const { setEmail, setAppPassword: setAppPasswordInStore } = useStore();

  const router = useRouter();

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setSuccessMessage(false);

    try {
      await sendContactEmail({
        email: sender,
        appPassword: appPassword,
      });

      const { address } = await getWalletAddress({ email: sender });
      setWalletAddress(address)

      setEmail(sender);
      setAppPasswordInStore(appPassword);

      setSuccessMessage(true);

    } catch (error) {
      console.error('Error: ', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-2xl shadow-md rounded-lg p-6 bg-gray-100 mb-20">
      <h2 className="text-2xl font-bold mb-2 text-gray-800 text-center">Create Account</h2>
      <p className="text-lg text-gray-400 mb-6 text-center">
        Email a relayer to create an account.
      </p>
      <form className="space-y-4" onSubmit={onSubmit}>
        <input
          type="email"
          value={sender}
          onChange={(e) => setSender(e.target.value)}
          placeholder="Email Address"
          required
          className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <input
          type="password"
          value={appPassword}
          onChange={(e) => setAppPassword(e.target.value)}
          placeholder="App Password"
          required
          className="w-full px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          type="submit"
          className={`w-full px-6 py-2 rounded-lg bg-beige text-black font-medium hover:bg-opacity-90 transition focus:outline-none focus:ring-2 focus:ring-beige focus:ring-offset-2 focus:ring-offset-black ${
            loading ? 'opacity-50 cursor-not-allowed' : ''
          }`}
          style={{ backgroundColor: '#f5c89c' }}
          disabled={loading}
        >
          {loading ? 'Sending...' : 'Create'}
        </button>
      </form>

      {/* Success message */}
      {successMessage && (
        <div className="mt-6 p-4 text-green-600 bg-green-100 rounded-lg">
          <p className="text-center text-xl">
            Account created successfully! Your XION account is {walletAddress} <br />
            For more information, please check your email.
          </p>
          <div className="flex justify-center mt-4">
            <button
              onClick={() => router.push('/transfer')} // Redirect when the button is clicked
              className="px-6 py-2 rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700 transition focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              Go to transfer section
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
