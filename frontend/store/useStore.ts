import { create } from 'zustand';

interface StoreState {
  email: string;
  appPassword: string;
  setEmail: (email: string) => void;
  setAppPassword: (appPassword: string) => void;
}

export const useStore = create<StoreState>((set) => ({
  email: '',
  appPassword: '',
  setEmail: (email) => set({ email }),
  setAppPassword: (appPassword) => set({ appPassword }),
}));