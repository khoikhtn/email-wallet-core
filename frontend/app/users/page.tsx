"use client";

import { useAppContext } from "@/hooks/AppContext";
import Link from "next/link";

export default function UsersPage() {
  const { email } = useAppContext();

  return (
    <div className="flex flex-col items-center justify-center min-h-screen p-4">
      <h1 className="text-2xl font-bold">Users Page</h1>
      <p className="mt-4 text-lg">
        {email ? `Username: ${email}` : "No username set."}
      </p>
      <Link href="/" className="mt-4 px-4 py-2 bg-gray-500 text-white rounded">
        Back to Home
      </Link>
    </div>
  );
}
