'use client'

import { createContext, useContext, useState, ReactNode } from "react"

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

  const contextValue: AppContextType = {
    email,
    setEmail,
    appPassword,
    setAppPassword
  }

  return (
    <AppContext.Provider value={contextValue}>
      {children}
    </AppContext.Provider>
  )
}

export const useAppContext = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error("useAppContext must be used within an AppProvider");
  }
  return context;
}

