import React from 'react';
import { Navbar } from './components/Navbar';
import { Hero } from './components/Hero';
import { ThreatSimulator } from './components/ThreatSimulator';
import { ArchitecturePipeline } from './components/ArchitecturePipeline';
import { SdkDocs } from './components/SdkDocs';
import { Benchmarks } from './components/Benchmarks';
import { Footer } from './components/Footer';

export const App: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#090A0F] text-slate-100 flex flex-col selection:bg-sentinel-emerald/30 selection:text-sentinel-emerald">
      <Navbar />
      <main className="flex-grow">
        <Hero />
        <ThreatSimulator />
        <ArchitecturePipeline />
        <SdkDocs />
        <Benchmarks />
      </main>
      <Footer />
    </div>
  );
};

export default App;
