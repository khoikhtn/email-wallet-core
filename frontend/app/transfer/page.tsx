'use client'

import React, { useEffect } from "react";
import Layout from "@/components/Layout";
import TransferSection from "@/components/TransferSection";
import { useAppContext } from "@/hooks/AppContext";

export default function TransferPage() {
  const { email } = useAppContext();

  useEffect(() => {
    console.log('Email: ', email);
  }, [email])


  return (
    <Layout>
      <TransferSection />
    </Layout>
  )
}