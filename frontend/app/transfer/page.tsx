import React from "react";
import Layout from "@/components/Layout";
import TransferSection from "@/components/TransferSection";
import { AppProvider } from "@/hooks/AppContext";

export default function TransferPage() {
  return (
    <AppProvider>
      <TransferSection />
    </AppProvider>
  )
}