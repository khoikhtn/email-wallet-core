"use client";

import { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface AppContextType {
  email: string | null;
  setEmail: (email: string | null) => void;
  appPassword: string | null;
  setAppPassword: (appPassword: string | null) => void;
  walletAddress: string | null;
  setWalletAddress: (walletAddress: string | null) => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider = ({ children }: { children: ReactNode }) => {
  const [email, setEmail] = useState<string | null>(null);
  const [appPassword, setAppPassword] = useState<string | null>(null);
  const [walletAddress, setWalletAddress] = useState<string | null>(null);

  // ✅ Load from localStorage on initial render
  useEffect(() => {
    const storedEmail = localStorage.getItem("email");
    const storedAppPassword = localStorage.getItem("appPassword");
    const walletAddress = localStorage.getItem("walletAddress");

    if (storedEmail) setEmail(storedEmail);
    if (storedAppPassword) setAppPassword(storedAppPassword);
    if (walletAddress) setWalletAddress(walletAddress);
  }, []);

  // ✅ Save to localStorage whenever state changes
  useEffect(() => {
    if (email) {
      localStorage.setItem("email", email);
    } else {
      localStorage.removeItem("email");
    }

    if (appPassword) {
      localStorage.setItem("appPassword", appPassword);
    } else {
      localStorage.removeItem("appPassword");
    }
    if (walletAddress) {
      localStorage.setItem("walletAddress", walletAddress);
    } else {
      localStorage.removeItem("walletAddress");
    }
  }, [email, appPassword, walletAddress]);

  return (
    <AppContext.Provider value={{ email, setEmail, appPassword, setAppPassword, walletAddress, setWalletAddress }}>
      {children}
    </AppContext.Provider>
  );
};

export const useAppContext = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error("useAppContext must be used within an AppProvider");
  }
  return context;
};
