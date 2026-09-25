import { createContext, useContext } from 'react';
import type { ReactNode } from 'react';
import { usePipeline } from '../hooks/usePipeline';
import type { Agent, MetricState, LogEntry, ScanReport } from '../types';

interface PipelineContextType {
  agents: Agent[];
  metrics: MetricState;
  logs: LogEntry[];
  isRunning: boolean;
  scanId: string | null;
  report: ScanReport | null;
  currentStage: number;
  backendConnected: boolean;
  startPipeline: (url: string) => void;
  stopPipeline: () => void;
}

const PipelineContext = createContext<PipelineContextType | undefined>(undefined);

export function PipelineProvider({ children }: { children: ReactNode }) {
  const pipeline = usePipeline();
  
  return (
    <PipelineContext.Provider value={pipeline}>
      {children}
    </PipelineContext.Provider>
  );
}

export function usePipelineContext() {
  const context = useContext(PipelineContext);
  if (context === undefined) {
    throw new Error('usePipelineContext must be used within a PipelineProvider');
  }
  return context;
}
