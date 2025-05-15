'use client'

import React, { useEffect } from "react";
import Layout from "@/components/Layout";
import TransactionsHistory from "@/components/TransactionsHistory";
import { useAppContext } from "@/hooks/AppContext";

export default function TransactionsHistoryPage() {
  const { walletAddress } = useAppContext();

  useEffect(() => {
    console.log('Email: ', walletAddress);
  }, [walletAddress])

  return (
    <Layout>
      <TransactionsHistory />
    </Layout>
  )
}