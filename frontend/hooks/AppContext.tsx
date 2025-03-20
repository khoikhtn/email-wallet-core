"use client";

import { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface AppContextType {
  email: string | null;
  setEmail: (email: string | null) => void;
  appPassword: string | null;
  setAppPassword: (appPassword: string | null) => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider = ({ children }: { children: ReactNode }) => {
  const [email, setEmail] = useState<string | null>(null);
  const [appPassword, setAppPassword] = useState<string | null>(null);

  // ✅ Load from localStorage on initial render
  useEffect(() => {
    const storedEmail = localStorage.getItem("email");
    const storedAppPassword = localStorage.getItem("appPassword");

    if (storedEmail) setEmail(storedEmail);
    if (storedAppPassword) setAppPassword(storedAppPassword);
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
  }, [email, appPassword]);

  return (
    <AppContext.Provider value={{ email, setEmail, appPassword, setAppPassword }}>
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
