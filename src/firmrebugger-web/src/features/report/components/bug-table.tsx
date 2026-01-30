import { useState, Fragment, useEffect } from 'react';
import {KaplanMeier} from './kaplan-meier'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { TableMutateDrawer, TableForm } from './table-mutate-drawer';

interface BugTableProps {
  benchmark: string;
  openDrawer?: boolean;
  onOpenChange?: (open: boolean) => void;
  onDataUpdate?: (data: BinaryGroup[] | null) => void;
}

interface BugEntry {
  fuzzer: string;
  run: string;
  reached: number | null;
  triggered: number | null;
  detected: number | null;
}

interface FuzzerStats {
  meanReached: number | null;
  meanTriggered: number | null;
  meanDetected: number | null;
  runs: BugEntry[];
}

interface BugRow {
  bugId: string;
  fuzzerStats: Record<string, FuzzerStats>;
}

interface BinaryGroup {
  binary: string;
  bugs: BugRow[];
}

interface TooltipState {
  visible: boolean;
  x: number;
  y: number;
  content: { run: string; value: number | null }[];
  metric: string;
}

export function BugTable({ benchmark, openDrawer, onOpenChange, onDataUpdate }: BugTableProps) {

  const [expandedBinaries, setExpandedBinaries] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<BinaryGroup[] | null>(null);
  const [internalShowDrawer, setInternalShowDrawer] = useState(false);
  const showDrawer = typeof openDrawer === 'boolean' ? openDrawer : internalShowDrawer;
  const handleDrawerChange = (v: boolean) => {
    if (onOpenChange) {
      onOpenChange(v);
    } else {
      setInternalShowDrawer(v);
    }
  };
  const [tooltip, setTooltip] = useState<TooltipState>({
    visible: false,
    x: 0,
    y: 0,
    content: [],
    metric: ''
  });
  const [fuzzers, setFuzzers] = useState<string[]>([]);
  const [tableFormSelections, setTableFormSelections] = useState<TableForm | null>(null);
  const [tooltipEnabled, setTooltipEnabled] = useState(true);

  const [kmOpen, setKmOpen] = useState(false)
  const [kmBugId, setKmBugId] = useState<string | null>(null)
  const [kmFuzzerRuns, setKmFuzzerRuns] = useState<Record<string, Array<{ run: string; reached?: number | null; triggered?: number | null; detected?: number | null }>>>({})
  const [kmMetric, setKmMetric] = useState<'reached' | 'triggered' | 'detected'>('reached')

  const fetchBugData = (response: any) => {
    console.log('Received response:', response);
    
    setError(null);
    
    const tableData = response.table_data || response;
    
    if (!Array.isArray(tableData)) {
      setError(`Invalid data format: expected array, got ${typeof tableData}`);
      return;
    }
    
    setData(tableData);
    
    if (onDataUpdate) {
      onDataUpdate(tableData);
    }
    
    const fuzzerSet = new Set<string>();
    tableData.forEach((binaryGroup: BinaryGroup) => {
      if (binaryGroup.bugs && Array.isArray(binaryGroup.bugs)) {
        binaryGroup.bugs.forEach((bug: BugRow) => {
          if (bug.fuzzerStats && typeof bug.fuzzerStats === 'object') {
            Object.keys(bug.fuzzerStats).forEach(fuzzer => {
              fuzzerSet.add(fuzzer);
            });
          }
        });
      }
    });
    setFuzzers(Array.from(fuzzerSet).sort());
  };

  const toggleBinary = (binary: string) => {
    setExpandedBinaries(prev => {
      const newSet = new Set(prev);
      if (newSet.has(binary)) {
        newSet.delete(binary);
      } else {
        newSet.add(binary);
      }
      return newSet;
    });
  };

  const showTooltip = (e: React.MouseEvent, runs: BugEntry[], metric: 'reached' | 'triggered' | 'detected') => {
    if (!tooltipEnabled) return;

    const rect = e.currentTarget.getBoundingClientRect();
    const content = runs.map(run => ({
      run: run.run,
      value: run[metric]
    }));

    setTooltip({
      visible: true,
      x: rect.left + rect.width / 2,
      y: rect.top - 10,
      content,
      metric
    });
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const tooltipElement = document.querySelector('.tooltip-class');
      if (tooltipElement && !tooltipElement.contains(event.target as Node)) {
        setTooltip(prev => ({ ...prev, visible: false }));
      }
    };

    if (tooltip.visible) {
      document.addEventListener('mousedown', handleClickOutside);
    } else {
      document.removeEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [tooltip.visible]);

  if (!data) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
              <CardTitle>Bug Table</CardTitle>
              <CardDescription>
                {error ? `Error: ${error}` : 'No bug table configured yet'}
              </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center h-96 space-y-4">
            {error ? (
              <div className="text-red-500 text-center">
                <p className="font-semibold">Error loading data:</p>
                <p>{error}</p>
              </div>
            ) : (
              <p className="text-muted-foreground text-center">
                No bug table data available for {benchmark}.
                <br />
                Click "Configure" to generate some data.
              </p>
            )}
          </div>
        </CardContent>
        <TableMutateDrawer
          open={showDrawer}
          onOpenChange={handleDrawerChange}
          onSuccess={fetchBugData}
          benchmark={benchmark}
          initialValues={tableFormSelections ?? undefined}
          onSelectionsChange={(v) => setTableFormSelections(v)}
        />
      </Card>
    );
  }

  const formatValue = (val: number | null, hasSuccess: boolean = false) => {
    if (val === null) return 'null';
    if (!isFinite(val)) return 'infinite';
    console.log('Has Success:', hasSuccess);

    const totalSeconds = Math.floor(val);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  };

  const hasAnySuccess = (runs: BugEntry[], metric: 'reached' | 'triggered' | 'detected') => {
    return runs.some(run => run[metric] !== null);
  };

  const totalBugs = Array.isArray(data) ? data.reduce((sum, bg) => sum + bg.bugs.length, 0) : 0;

  const getBestValues = (bug: BugRow) => {
    const reached: number[] = [];
    const triggered: number[] = [];
    const detected: number[] = [];

    Object.values(bug.fuzzerStats).forEach(stats => {
      if (stats.meanReached !== null && isFinite(stats.meanReached)) reached.push(stats.meanReached);
      if (stats.meanTriggered !== null && isFinite(stats.meanTriggered)) triggered.push(stats.meanTriggered);
      if (stats.meanDetected !== null && isFinite(stats.meanDetected)) detected.push(stats.meanDetected);
    });

    return {
      bestReached: reached.length > 0 ? Math.min(...reached) : null,
      bestTriggered: triggered.length > 0 ? Math.min(...triggered) : null,
      bestDetected: detected.length > 0 ? Math.min(...detected) : null
    };
  };

  const isBestValue = (value: number | null, bestValue: number | null) => {
    return value !== null && bestValue !== null && Math.abs(value - bestValue) < 0.01;
  };

  const calculateFuzzerStats = (binaryGroup: BinaryGroup) => {
    const fuzzerStats: Record<string, { reached: string; triggered: string; detected: string; tooltips: Record<string, string> }> = {};

    fuzzers.forEach((fuzzer) => {
      let reachedBugs = 0;
      let triggeredBugs = 0;
      let detectedBugs = 0;
      const totalBugs = binaryGroup.bugs.length;

      binaryGroup.bugs.forEach((bug) => {
        const stats = bug.fuzzerStats[fuzzer];
        if (stats) {
          if (stats.runs.some((run) => run.reached !== null)) reachedBugs++;
          if (stats.runs.some((run) => run.triggered !== null)) triggeredBugs++;
          if (stats.runs.some((run) => run.detected !== null)) detectedBugs++;
        }
      });

      fuzzerStats[fuzzer] = {
        reached: totalBugs > 0 ? `${((reachedBugs / totalBugs) * 100).toFixed(1)}%` : '0.0%',
        triggered: totalBugs > 0 ? `${((triggeredBugs / totalBugs) * 100).toFixed(1)}%` : '0.0%',
        detected: totalBugs > 0 ? `${((detectedBugs / totalBugs) * 100).toFixed(1)}%` : '0.0%',
        tooltips: {
          reached: `${reachedBugs}/${totalBugs} bugs`,
          triggered: `${triggeredBugs}/${totalBugs} bugs`,
          detected: `${detectedBugs}/${totalBugs} bugs`,
        },
      };
    });

    return fuzzerStats;
  };

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Bug Table</CardTitle>
              <CardDescription>
                Showing {totalBugs} unique bug{totalBugs !== 1 ? 's' : ''} across {data.length} binar{data.length !== 1 ? 'ies' : 'y'} and {fuzzers.length} fuzzer{fuzzers.length !== 1 ? 's' : ''} for {benchmark}. 
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border relative">
            <div className="relative w-full overflow-auto">
              <table className="w-full caption-bottom text-sm">
                <thead className="[&_tr]:border-b bg-muted/50">
                  <tr className="border-b">
                    <th className="h-12 px-3 text-left align-middle font-bold text-muted-foreground w-24" rowSpan={2}>
                      Binary
                    </th>
                    {fuzzers.map((fuzzer) => (
                      <th
                        key={fuzzer}
                        className="h-12 px-2 text-center align-middle font-bold text-muted-foreground border-l"
                        colSpan={3}
                      >
                        {fuzzer}
                      </th>
                    ))}
                  </tr>
                  <tr className="border-b">
                    {fuzzers.map((fuzzer) => (
                      <Fragment key={fuzzer}>
                        <th className="h-10 px-1.5 text-center align-middle text-xs font-semibold text-muted-foreground border-l w-16">
                          R
                        </th>
                        <th className="h-10 px-1.5 text-center align-middle text-xs font-semibold text-muted-foreground w-16">
                          T
                        </th>
                        <th className="h-10 px-1.5 text-center align-middle text-xs font-semibold text-muted-foreground w-16">
                          D
                        </th>
                      </Fragment>
                    ))}
                  </tr>
                </thead>
                <tbody className="[&_tr:last-child]:border-0">
                  {data.length > 0 ? (
                    data.map((binaryGroup) => {
                      const isExpanded = expandedBinaries.has(binaryGroup.binary);
                      return (
                        <Fragment key={binaryGroup.binary}>
                          <tr
                            className="border-b bg-muted/20 cursor-pointer hover:bg-muted/40 transition-colors"
                            onClick={() => toggleBinary(binaryGroup.binary)}
                          >
                            <td className="px-3 py-2 align-middle font-semibold">
                              <div className="flex items-center gap-2">
                                {isExpanded ? (
                                  <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                                ) : (
                                  <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                                )}
                                <span className="truncate">{binaryGroup.binary}</span>
                                <span className="text-xs font-normal text-muted-foreground whitespace-nowrap">
                                  ({binaryGroup.bugs.length})
                                </span>
                              </div>
                            </td>
                            {fuzzers.map((fuzzer) => {
                              const stats = calculateFuzzerStats(binaryGroup)[fuzzer];
                              return (
                                <Fragment key={fuzzer}>
                                  <td className="text-center text-muted-foreground">{stats.reached}</td>
                                  <td className="text-center text-muted-foreground">{stats.triggered}</td>
                                  <td className="text-center text-muted-foreground">{stats.detected}</td>
                                </Fragment>
                              );
                            })}
                          </tr>
                          {isExpanded && binaryGroup.bugs.map((bug) => {
                            const bestValues = getBestValues(bug);

                            return (
                              <tr
                                key={`${binaryGroup.binary}-${bug.bugId}`}
                                className="border-b transition-colors hover:bg-muted/30"
                              >
                                <td className="px-3 py-2 align-middle text-muted-foreground text-sm pl-6">
                                  <button
                                    className="text-left underline underline-offset-1 text-sm hover:text-primary"
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      const runsByFuzzer: Record<string, Array<{ run: string; reached?: number | null; triggered?: number | null; detected?: number | null }>> = {}
                                      Object.entries(bug.fuzzerStats || {}).forEach(([f, stats]) => {
                                        runsByFuzzer[f] = (stats as any).runs || []
                                      })
                                      setKmFuzzerRuns(runsByFuzzer)
                                      setKmBugId(bug.bugId)
                                      setKmMetric('reached')
                                      setKmOpen(true)
                                    }}
                                  >
                                    {bug.bugId}
                                  </button>
                                </td>
                                {fuzzers.map((fuzzer) => {
                                  const stats = bug.fuzzerStats[fuzzer];
                                  const isReachedBest = stats && isBestValue(stats.meanReached, bestValues.bestReached);
                                  const isTriggeredBest = stats && isBestValue(stats.meanTriggered, bestValues.bestTriggered);
                                  const isDetectedBest = stats && isBestValue(stats.meanDetected, bestValues.bestDetected);

                                  const hasReached = stats && hasAnySuccess(stats.runs, 'reached');
                                  const hasTriggered = stats && hasAnySuccess(stats.runs, 'triggered');
                                  const hasDetected = stats && hasAnySuccess(stats.runs, 'detected');

                                  return (
                                    <Fragment key={fuzzer}>
                                      <td 
                                        className={`px-1.5 py-2 text-center align-middle border-l text-xs cursor-pointer transition-colors ${
                                          isReachedBest 
                                            ? 'bg-green-100 dark:bg-green-900/30 font-semibold text-green-900 dark:text-green-300' 
                                            : 'hover:bg-muted/50'
                                        } ${stats?.meanReached === null && hasReached ? 'text-yellow-600 dark:text-yellow-400 font-semibold' : ''}`}
                                        onMouseEnter={(e) => tooltipEnabled && stats && stats.runs.length > 0 && showTooltip(e, stats.runs, 'reached')}
                                        onMouseLeave={() => tooltipEnabled && setTooltip(prev => ({ ...prev, visible: false }))}
                                      >
                                        {stats ? formatValue(stats.meanReached, hasReached) : '✗'}
                                      </td>
                                      <td 
                                        className={`px-1.5 py-2 text-center align-middle text-xs cursor-pointer transition-colors ${
                                          isTriggeredBest 
                                            ? 'bg-green-100 dark:bg-green-900/30 font-semibold text-green-900 dark:text-green-300' 
                                            : 'hover:bg-muted/50'
                                        } ${stats?.meanTriggered === null && hasTriggered ? 'text-yellow-600 dark:text-yellow-400 font-semibold' : ''}`}
                                        onMouseEnter={(e) => tooltipEnabled && stats && stats.runs.length > 0 && showTooltip(e, stats.runs, 'triggered')}
                                        onMouseLeave={() => tooltipEnabled && setTooltip(prev => ({ ...prev, visible: false }))}
                                      >
                                        {stats ? formatValue(stats.meanTriggered, hasTriggered) : '✗'}
                                      </td>
                                      <td 
                                        className={`px-1.5 py-2 text-center align-middle text-xs cursor-pointer transition-colors ${
                                          isDetectedBest 
                                            ? 'bg-green-100 dark:bg-green-900/30 font-semibold text-green-900 dark:text-green-300' 
                                            : 'hover:bg-muted/50'
                                        } ${stats?.meanDetected === null && hasDetected ? 'text-yellow-600 dark:text-yellow-400 font-semibold' : ''}`}
                                        onMouseEnter={(e) => tooltipEnabled && stats && stats.runs.length > 0 && showTooltip(e, stats.runs, 'detected')}
                                        onMouseLeave={() => tooltipEnabled && setTooltip(prev => ({ ...prev, visible: false }))}
                                      >
                                        {stats ? formatValue(stats.meanDetected, hasDetected) : '✗'}
                                      </td>
                                    </Fragment>
                                  );
                                })}
                              </tr>
                            );
                          })}
                        </Fragment>
                      );
                    })
                  ) : (
                    <tr>
                      <td
                        colSpan={2 + fuzzers.length * 3}
                        className="h-24 text-center text-muted-foreground"
                      >
                        No bug data available
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {tooltip.visible && tooltip.content.length > 0 && (
              <div
                className="fixed z-50 px-3 py-2 text-sm bg-popover text-popover-foreground border rounded-md shadow-md pointer-events-none"
                style={{
                  left: `${tooltip.x}px`,
                  top: `${tooltip.y}px`,
                  transform: 'translate(-50%, -100%)',
                  maxWidth: '250px'
                }}
              >
                <div className="font-semibold mb-1 capitalize">{tooltip.metric} Times</div>
                <div className="space-y-1">
                  {tooltip.content.map((item, idx) => (
                    <div key={idx} className="flex justify-between gap-4 text-xs">
                      <span className="text-muted-foreground">{item.run}:</span>
                      <span className="font-mono">{formatValue(item.value)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-green-100 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded"></div>
                <span>Best time for bug</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-yellow-600 dark:text-yellow-400">✗</span>
                <span>Success in at least 1 run</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold">R</span> = Reached
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold">T</span> = Triggered
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold">D</span> = Detected
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                className={`text-xs underline ${tooltipEnabled ? 'text-primary' : 'text-muted-foreground'}`}
                onClick={() => setTooltipEnabled(!tooltipEnabled)}
              >
                {tooltipEnabled ? 'Disable Hover' : 'Enable Hover'}
              </button>
            </div>
          </div>
        </CardContent>
      </Card>

        <TableMutateDrawer
          open={showDrawer}
          onOpenChange={handleDrawerChange}
          onSuccess={fetchBugData}
          benchmark={benchmark}
          initialValues={tableFormSelections ?? undefined}
          onSelectionsChange={(v) => setTableFormSelections(v)}
        />

        {kmBugId && (
          <KaplanMeier
            open={kmOpen}
            onOpenChange={(v: boolean) => {
              setKmOpen(v)
              if (!v) setKmMetric('reached')
            }}
            bugId={kmBugId}
            fuzzerRuns={kmFuzzerRuns}
            metric={kmMetric}
            onMetricChange={setKmMetric}
          />
        )}
    </>
  );
}