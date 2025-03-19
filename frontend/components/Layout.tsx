'use client';

import React from 'react';
import Header from './Header';
import Footer from './Footer';
import MiddleContent from './Content';

interface LayoutProps {
  children: React.ReactNode; // The child components (e.g., different forms)
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="flex flex-col min-h-screen">
      <Header />
      <main className="flex-grow flex flex-col items-center justify-center p-4 sm:p-8">
        <MiddleContent />
        {children}
      </main>
      <Footer />
    </div>
  );
}
