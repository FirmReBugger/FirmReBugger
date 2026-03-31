import { useState, Fragment, useEffect, useRef } from "react";
import { KaplanMeier } from "./kaplan-meier";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ChevronDown, ChevronRight, Download, MousePointerClick } from "lucide-react";
import { TableMutateDrawer, TableForm } from "./table-mutate-drawer";
import { useApiUrl, useApiUrlLoading } from "@/context/api-url-context";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";

interface BugTableProps {
  benchmark: string;
  openDrawer?: boolean;
  onOpenChange?: (open: boolean) => void;
  onDataUpdate?: (data: BinaryGroup[] | null) => void;
  onReportPathsUpdate?: (paths: string[]) => void;
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

const isErrorBugId = (bugId: string | undefined | null) =>
  typeof bugId === "string" && bugId.toUpperCase().startsWith("ERROR");

const filterErrorBugs = (tableData: BinaryGroup[]): BinaryGroup[] =>
  tableData
    .map((binaryGroup) => ({
      ...binaryGroup,
      bugs: (binaryGroup.bugs || []).filter((bug) => !isErrorBugId(bug?.bugId)),
    }))
    .filter((binaryGroup) => binaryGroup.bugs.length > 0);

export function BugTable({
  benchmark,
  openDrawer,
  onOpenChange,
  onDataUpdate,
  onReportPathsUpdate,
}: BugTableProps) {
  const API_URL = useApiUrl();
  const apiUrlLoading = useApiUrlLoading();

  const [expandedBinaries, setExpandedBinaries] = useState<Set<string>>(
    new Set(),
  );
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<BinaryGroup[] | null>(null);
  const [isAutoFetching, setIsAutoFetching] = useState(false);
  const [internalShowDrawer, setInternalShowDrawer] = useState(false);
  const showDrawer =
    typeof openDrawer === "boolean" ? openDrawer : internalShowDrawer;
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
    metric: "",
  });
  const [consistencyTooltip, setConsistencyTooltip] = useState<{
    visible: boolean;
    x: number;
    y: number;
    fuzzer: string;
    B: number;
    T: number;
    sumC: number;
    pct: number;
  } | null>(null);
  const [fuzzers, setFuzzers] = useState<string[]>([]);
  const [tableFormSelections, setTableFormSelections] =
    useState<TableForm | null>(() => {
      try {
        const stored = localStorage.getItem(`report-config-${benchmark}`);
        return stored ? (JSON.parse(stored) as TableForm) : null;
      } catch {
        return null;
      }
    });
  const initialSelectionsRef = useRef(tableFormSelections);
  const [tooltipEnabled, setTooltipEnabled] = useState(true);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [exportPdfBase64, setExportPdfBase64] = useState("");
  const [exportLatexCode, setExportLatexCode] = useState("");
  const [exportPdfError, setExportPdfError] = useState<string | null>(null);
  const [showTexPreview, setShowTexPreview] = useState(false);
  const [exportFilename, setExportFilename] = useState("summary_table.pdf");

  const [kmOpen, setKmOpen] = useState(false);
  const [kmBugId, setKmBugId] = useState<string | null>(null);
  const [kmFuzzerRuns, setKmFuzzerRuns] = useState<
    Record<
      string,
      Array<{
        run: string;
        reached?: number | null;
        triggered?: number | null;
        detected?: number | null;
      }>
    >
  >({});
  const [kmMetric, setKmMetric] = useState<
    "reached" | "triggered" | "detected"
  >("detected");

  const getSelectedReportPaths = (form: TableForm | null): string[] => {
    if (!form) return [];
    const selectedReportPaths: string[] = [];
    Object.values(form.selectedReports || {}).forEach((fuzzerReports) => {
      Object.values(fuzzerReports || {}).forEach((reportPath) => {
        if (reportPath) {
          selectedReportPaths.push(reportPath);
        }
      });
    });
    return selectedReportPaths;
  };

  useEffect(() => {
    if (!onReportPathsUpdate) return;
    onReportPathsUpdate(getSelectedReportPaths(tableFormSelections));
  }, [tableFormSelections, onReportPathsUpdate]);

  useEffect(() => {
    if (apiUrlLoading) return;

    const selections = initialSelectionsRef.current;
    if (!selections) return;

    const selectedFuzzers = selections.fuzzer;
    const selectedReportPaths: string[] = [];
    Object.values(selections.selectedReports).forEach((fuzzerReports) => {
      Object.values(fuzzerReports).forEach((reportPath) => {
        selectedReportPaths.push(reportPath);
      });
    });

    if (selectedFuzzers.length === 0 || selectedReportPaths.length === 0)
      return;

    setIsAutoFetching(true);
    fetch(`${API_URL}/api/table/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        benchmark,
        fuzzers: selectedFuzzers,
        report_paths: selectedReportPaths,
      }),
    })
      .then((res) => {
        if (!res.ok)
          return res
            .json()
            .then((err) =>
              Promise.reject(
                new Error(err.error || "Failed to restore configuration"),
              ),
            );
        return res.json();
      })
      .then((result) => {
        fetchBugData(result);
      })
      .catch((err) => {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to restore configuration",
        );
      })
      .finally(() => {
        setIsAutoFetching(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiUrlLoading]);

  const fetchBugData = (response: any) => {
    console.log("Received response:", response);

    setError(null);

    const tableData = response.table_data || response;

    if (!Array.isArray(tableData)) {
      setError(`Invalid data format: expected array, got ${typeof tableData}`);
      return;
    }

    const filteredTableData = filterErrorBugs(tableData as BinaryGroup[]);

    setData(filteredTableData);

    if (onDataUpdate) {
      onDataUpdate(filteredTableData);
    }

    const fuzzerSet = new Set<string>();
    filteredTableData.forEach((binaryGroup: BinaryGroup) => {
      if (binaryGroup.bugs && Array.isArray(binaryGroup.bugs)) {
        binaryGroup.bugs.forEach((bug: BugRow) => {
          if (bug.fuzzerStats && typeof bug.fuzzerStats === "object") {
            Object.keys(bug.fuzzerStats).forEach((fuzzer) => {
              fuzzerSet.add(fuzzer);
            });
          }
        });
      }
    });
    setFuzzers(Array.from(fuzzerSet).sort());
  };

  const handleSuccess = (response: any, query?: TableForm) => {
    fetchBugData(response);
    if (query) {
      try {
        localStorage.setItem(
          `report-config-${benchmark}`,
          JSON.stringify(query),
        );
        setTableFormSelections(query);
      } catch {
        // ignore
      }
    }
  };

  const handleExportTable = async () => {
    const reportPaths = getSelectedReportPaths(tableFormSelections);
    if (reportPaths.length === 0) {
      toast.error("Configure the table first to select report paths");
      return;
    }

    setExportLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/report/export-latex`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          benchmark,
          report_paths: reportPaths,
        }),
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || "Failed to export LaTeX table");
      }

      const pdfPreview = result.preview_pdf_base64 || result.pdf_base64 || "";
      setExportPdfBase64(pdfPreview);
      setExportLatexCode(result.latex_code || "");
      setExportPdfError(result.pdf_error || null);
      setShowTexPreview(!pdfPreview && Boolean(result.latex_code));
      setExportFilename(
        result.filename || `${benchmark.toLowerCase()}_summary_table.pdf`,
      );
      setExportDialogOpen(true);

      if (!pdfPreview && result.pdf_error) {
        toast.error("PDF preview unavailable. Showing TeX output instead.");
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to export LaTeX table");
    } finally {
      setExportLoading(false);
    }
  };

  const handleDownloadExport = () => {
    if (!exportPdfBase64) return;
    const bytes = atob(exportPdfBase64);
    const buffer = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      buffer[i] = bytes.charCodeAt(i);
    }
    const blob = new Blob([buffer], { type: "application/pdf" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = exportFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Table PDF downloaded");
  };

  const toggleBinary = (binary: string) => {
    setExpandedBinaries((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(binary)) {
        newSet.delete(binary);
      } else {
        newSet.add(binary);
      }
      return newSet;
    });
  };

  const showTooltip = (
    e: React.MouseEvent,
    runs: BugEntry[],
    metric: "reached" | "triggered" | "detected",
  ) => {
    if (!tooltipEnabled) return;

    const rect = e.currentTarget.getBoundingClientRect();
    const content = runs.map((run) => ({
      run: run.run,
      value: run[metric],
    }));

    setTooltip({
      visible: true,
      x: rect.left + rect.width / 2,
      y: rect.top - 10,
      content,
      metric,
    });
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const tooltipElement = document.querySelector(".tooltip-class");
      if (tooltipElement && !tooltipElement.contains(event.target as Node)) {
        setTooltip((prev) => ({ ...prev, visible: false }));
      }
    };

    if (tooltip.visible) {
      document.addEventListener("mousedown", handleClickOutside);
    } else {
      document.removeEventListener("mousedown", handleClickOutside);
    }

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [tooltip.visible]);

  if (!data) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Bug Table</CardTitle>
            <CardDescription>
              {error ? `Error: ${error}` : "No bug table configured yet"}
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
            ) : isAutoFetching ? (
              <p className="text-muted-foreground text-center animate-pulse">
                Restoring previous configuration for {benchmark}…
              </p>
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
          onSuccess={handleSuccess}
          benchmark={benchmark}
          initialValues={tableFormSelections ?? undefined}
          onSelectionsChange={(v) => setTableFormSelections(v)}
        />
      </Card>
    );
  }

  const formatValue = (val: number | null, hasSuccess: boolean = false) => {
    if (val === null) return "✗";
    if (!isFinite(val)) return "infinite";
    console.log("Has Success:", hasSuccess);

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

  const hasAnySuccess = (
    runs: BugEntry[],
    metric: "reached" | "triggered" | "detected",
  ) => {
    return runs.some((run) => run[metric] !== null);
  };

  const getBestValues = (bug: BugRow) => {
    const reached: number[] = [];
    const triggered: number[] = [];
    const detected: number[] = [];

    Object.values(bug.fuzzerStats).forEach((stats) => {
      if (stats.meanReached !== null && isFinite(stats.meanReached))
        reached.push(stats.meanReached);
      if (stats.meanTriggered !== null && isFinite(stats.meanTriggered))
        triggered.push(stats.meanTriggered);
      if (stats.meanDetected !== null && isFinite(stats.meanDetected))
        detected.push(stats.meanDetected);
    });

    return {
      bestReached: reached.length > 0 ? Math.min(...reached) : null,
      bestTriggered: triggered.length > 0 ? Math.min(...triggered) : null,
      bestDetected: detected.length > 0 ? Math.min(...detected) : null,
    };
  };

  const isBestValue = (value: number | null, bestValue: number | null) => {
    return (
      value !== null && bestValue !== null && Math.abs(value - bestValue) < 0.01
    );
  };

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Bug Table</CardTitle>
              <CardDescription>
                Interactive table to show reached, triggered and detected metrics for each bug and fuzzer combination.
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleExportTable}
              disabled={exportLoading}
            >
              <Download className="h-4 w-4 mr-2" />
              {exportLoading ? "Preparing..." : "Export"}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border relative">
            <div className="relative w-full overflow-auto">
              <table className="w-full caption-bottom text-sm">
                <thead className="[&_tr]:border-b bg-muted/50">
                  <tr className="border-b">
                    <th
                      className="h-12 px-3 text-left align-middle font-bold text-muted-foreground w-24"
                      rowSpan={2}
                    >
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
                      const isExpanded = expandedBinaries.has(
                        binaryGroup.binary,
                      );
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
                                <span className="truncate">
                                  {binaryGroup.binary}
                                </span>
                                <span className="text-xs font-normal text-muted-foreground whitespace-nowrap">
                                  ({binaryGroup.bugs.length})
                                </span>
                              </div>
                            </td>
                            {fuzzers.map((fuzzer) => {
                              const bugs = binaryGroup.bugs;
                              const B = bugs.length;
                              let sum = 0;
                              bugs.forEach((bug) => {
                                const stats = bug.fuzzerStats[fuzzer];
                                if (!stats || stats.runs.length === 0) return;
                                const T = stats.runs.length;
                                const c = stats.runs.filter((r) => r.detected !== null).length;
                                sum += c / T;
                              });
                              const consistency = B > 0 ? sum / B : null;
                              const pct = consistency !== null ? consistency * 100 : null;
                              // pre-compute per-bug T for tooltip (use first bug's run count as representative)
                              const repT = bugs.find((bug) => bug.fuzzerStats[fuzzer]?.runs?.length)?.fuzzerStats[fuzzer]?.runs?.length ?? 0;
                              const sumC = bugs.reduce((acc, bug) => {
                                const s = bug.fuzzerStats[fuzzer];
                                if (!s || s.runs.length === 0) return acc;
                                return acc + s.runs.filter((r) => r.detected !== null).length;
                              }, 0);
                              return (
                                <td
                                  key={fuzzer}
                                  colSpan={3}
                                  className="border-l px-2 py-2 text-center cursor-default"
                                  onMouseEnter={(e) => {
                                    if (pct === null || !tooltipEnabled) return;
                                    const rect = e.currentTarget.getBoundingClientRect();
                                    setConsistencyTooltip({
                                      visible: true,
                                      x: rect.left + rect.width / 2,
                                      y: rect.top - 10,
                                      fuzzer,
                                      B,
                                      T: repT,
                                      sumC,
                                      pct,
                                    });
                                  }}
                                  onMouseLeave={() => setConsistencyTooltip(null)}
                                >
                                  <span
                                    className={`inline-block text-[11px] font-mono tabular-nums px-1.5 py-0.5 rounded-md border ${
                                      pct === null
                                        ? "border-border text-muted-foreground bg-muted/30"
                                        : pct >= 70
                                        ? "border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 font-semibold"
                                        : pct >= 30
                                        ? "border-yellow-300 dark:border-yellow-700 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400"
                                        : "border-border text-muted-foreground bg-muted/30"
                                    }`}
                                  >
                                    {pct !== null ? `${pct.toFixed(1)}%` : "—"}
                                  </span>
                                </td>
                              );
                            })}
                          </tr>
                          {isExpanded &&
                            binaryGroup.bugs.map((bug) => {
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
                                        e.stopPropagation();
                                        const runsByFuzzer: Record<
                                          string,
                                          Array<{
                                            run: string;
                                            reached?: number | null;
                                            triggered?: number | null;
                                            detected?: number | null;
                                          }>
                                        > = {};
                                        Object.entries(
                                          bug.fuzzerStats || {},
                                        ).forEach(([f, stats]) => {
                                          runsByFuzzer[f] =
                                            (stats as any).runs || [];
                                        });
                                        setKmFuzzerRuns(runsByFuzzer);
                                        setKmBugId(bug.bugId);
                                        setKmMetric("detected");
                                        setKmOpen(true);
                                      }}
                                    >
                                      {bug.bugId}
                                    </button>
                                  </td>
                                  {fuzzers.map((fuzzer) => {
                                    const stats = bug.fuzzerStats[fuzzer];
                                    const isReachedBest =
                                      stats &&
                                      isBestValue(
                                        stats.meanReached,
                                        bestValues.bestReached,
                                      );
                                    const isTriggeredBest =
                                      stats &&
                                      isBestValue(
                                        stats.meanTriggered,
                                        bestValues.bestTriggered,
                                      );
                                    const isDetectedBest =
                                      stats &&
                                      isBestValue(
                                        stats.meanDetected,
                                        bestValues.bestDetected,
                                      );

                                    const hasReached =
                                      stats &&
                                      hasAnySuccess(stats.runs, "reached");
                                    const hasTriggered =
                                      stats &&
                                      hasAnySuccess(stats.runs, "triggered");
                                    const hasDetected =
                                      stats &&
                                      hasAnySuccess(stats.runs, "detected");

                                    return (
                                      <Fragment key={fuzzer}>
                                        <td
                                          className={`px-1.5 py-2 text-center align-middle border-l text-xs cursor-pointer transition-colors ${
                                            isReachedBest
                                              ? "bg-green-100 dark:bg-green-900/30 font-semibold text-green-900 dark:text-green-300"
                                              : "hover:bg-muted/50"
                                          } ${stats?.meanReached === null && hasReached ? "text-yellow-600 dark:text-yellow-400 font-semibold" : ""}`}
                                          onMouseEnter={(e) =>
                                            tooltipEnabled &&
                                            stats &&
                                            stats.runs.length > 0 &&
                                            showTooltip(
                                              e,
                                              stats.runs,
                                              "reached",
                                            )
                                          }
                                          onMouseLeave={() =>
                                            tooltipEnabled &&
                                            setTooltip((prev) => ({
                                              ...prev,
                                              visible: false,
                                            }))
                                          }
                                        >
                                          {stats
                                            ? formatValue(
                                                stats.meanReached,
                                                hasReached,
                                              )
                                            : "✗"}
                                        </td>
                                        <td
                                          className={`px-1.5 py-2 text-center align-middle text-xs cursor-pointer transition-colors ${
                                            isTriggeredBest
                                              ? "bg-green-100 dark:bg-green-900/30 font-semibold text-green-900 dark:text-green-300"
                                              : "hover:bg-muted/50"
                                          } ${stats?.meanTriggered === null && hasTriggered ? "text-yellow-600 dark:text-yellow-400 font-semibold" : ""}`}
                                          onMouseEnter={(e) =>
                                            tooltipEnabled &&
                                            stats &&
                                            stats.runs.length > 0 &&
                                            showTooltip(
                                              e,
                                              stats.runs,
                                              "triggered",
                                            )
                                          }
                                          onMouseLeave={() =>
                                            tooltipEnabled &&
                                            setTooltip((prev) => ({
                                              ...prev,
                                              visible: false,
                                            }))
                                          }
                                        >
                                          {stats
                                            ? formatValue(
                                                stats.meanTriggered,
                                                hasTriggered,
                                              )
                                            : "✗"}
                                        </td>
                                        <td
                                          className={`px-1.5 py-2 text-center align-middle text-xs cursor-pointer transition-colors ${
                                            isDetectedBest
                                              ? "bg-green-100 dark:bg-green-900/30 font-semibold text-green-900 dark:text-green-300"
                                              : "hover:bg-muted/50"
                                          } ${stats?.meanDetected === null && hasDetected ? "text-yellow-600 dark:text-yellow-400 font-semibold" : ""}`}
                                          onMouseEnter={(e) =>
                                            tooltipEnabled &&
                                            stats &&
                                            stats.runs.length > 0 &&
                                            showTooltip(
                                              e,
                                              stats.runs,
                                              "detected",
                                            )
                                          }
                                          onMouseLeave={() =>
                                            tooltipEnabled &&
                                            setTooltip((prev) => ({
                                              ...prev,
                                              visible: false,
                                            }))
                                          }
                                        >
                                          {stats
                                            ? formatValue(
                                                stats.meanDetected,
                                                hasDetected,
                                              )
                                            : "✗"}
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

            {consistencyTooltip?.visible && (
              <div
                className="fixed z-50 bg-popover text-popover-foreground border rounded-lg shadow-lg pointer-events-none"
                style={{
                  left: `${consistencyTooltip.x}px`,
                  top: `${consistencyTooltip.y}px`,
                  transform: "translate(-50%, -100%)",
                  minWidth: "200px",
                  marginBottom: "6px",
                }}
              >
                <div className="px-3 pt-2.5 pb-1 border-b">
                  <span className="text-xs font-semibold tracking-wide">
                    Consistency (hover for formula)
                  </span>
                </div>
                <div className="px-3 py-2.5 flex flex-col items-center gap-2">
                  {/* visual fraction */}
                  <div className="flex items-center gap-1.5 text-xs">
                    <span className="text-muted-foreground text-[11px]">C =</span>
                    <div className="inline-flex flex-col items-center leading-none">
                      <span className="pb-0.5 font-mono">
                        Σ c<sub>f,b</sub>
                      </span>
                      <span className="w-full border-t border-foreground/60" />
                      <span className="pt-0.5 font-mono">|B| × T</span>
                    </div>
                  </div>
                  {/* computed values */}
                  <div className="w-full rounded-md bg-muted/50 px-2.5 py-1.5 space-y-0.5 text-[11px] font-mono">
                    <div className="flex justify-between gap-3">
                      <span className="text-muted-foreground">Σ c<sub>f,b</sub></span>
                      <span>{consistencyTooltip.sumC}</span>
                    </div>
                    <div className="flex justify-between gap-3">
                      <span className="text-muted-foreground">|B|</span>
                      <span>{consistencyTooltip.B} bug{consistencyTooltip.B !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="flex justify-between gap-3">
                      <span className="text-muted-foreground">T</span>
                      <span>{consistencyTooltip.T} trial{consistencyTooltip.T !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="flex justify-between gap-3 border-t border-border pt-0.5 mt-0.5">
                      <span className="text-muted-foreground">= </span>
                      <span className="font-semibold">{consistencyTooltip.pct.toFixed(1)}%</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {tooltip.visible && tooltip.content.length > 0 && (
              <div
                className="fixed z-50 px-3 py-2 text-sm bg-popover text-popover-foreground border rounded-md shadow-md pointer-events-none"
                style={{
                  left: `${tooltip.x}px`,
                  top: `${tooltip.y}px`,
                  transform: "translate(-50%, -100%)",
                  maxWidth: "250px",
                }}
              >
                <div className="font-semibold mb-1 capitalize">
                  {tooltip.metric} Times
                </div>
                <div className="space-y-1">
                  {tooltip.content.map((item, idx) => (
                    <div
                      key={idx}
                      className="flex justify-between gap-4 text-xs"
                    >
                      <span className="text-muted-foreground">{item.run}:</span>
                      <span className="font-mono">
                        {formatValue(item.value)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 flex flex-col gap-1.5 text-xs text-muted-foreground">
            <div className="flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-green-100 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded"></div>
                <span>Best time for bug</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-yellow-600 dark:text-yellow-400">
                  ✗
                </span>
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
              <div className="flex items-center gap-2">
                <span className="inline-block text-[11px] font-mono px-1.5 py-0.5 rounded-md border border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400">75%</span>
                <span>= consistency (hover for formula)</span>
              </div>
              <div className="flex items-center gap-2">
                <MousePointerClick className="h-3.5 w-3.5" />
                <span>Click a bug ID for survival graph</span>
              </div>
              <button
                className={`ml-auto text-xs underline ${tooltipEnabled ? "text-primary" : "text-muted-foreground"}`}
                onClick={() => setTooltipEnabled(!tooltipEnabled)}
              >
                {tooltipEnabled ? "Disable Hover" : "Enable Hover"}
              </button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Dialog open={exportDialogOpen} onOpenChange={setExportDialogOpen}>
        <DialogContent className="!w-[96vw] !max-w-[1700px] h-[90vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>Table Export Preview</DialogTitle>
            <DialogDescription>
              Generated from selected reports for {benchmark}. You can preview
              the PDF or inspect the generated TeX.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowTexPreview((v) => !v)}
              disabled={!exportLatexCode}
            >
              {showTexPreview ? "Show PDF" : "Show TeX"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadExport}
              disabled={!exportPdfBase64}
            >
              <Download className="h-4 w-4 mr-2" />
              Download PDF
            </Button>
          </div>
          <div className="flex-1 min-h-0 rounded-md border bg-muted/30">
            {showTexPreview ? (
              <pre className="h-full w-full overflow-auto p-4 text-xs leading-relaxed whitespace-pre-wrap">
                {exportLatexCode || "No TeX generated."}
              </pre>
            ) : exportPdfBase64 ? (
              <iframe
                title="Table PDF preview"
                src={`data:application/pdf;base64,${exportPdfBase64}`}
                className="w-full h-full"
              />
            ) : (
              <div className="text-sm text-muted-foreground p-4 space-y-2">
                <div>No PDF preview generated.</div>
                {exportPdfError && (
                  <div className="text-xs whitespace-pre-wrap">{exportPdfError}</div>
                )}
                {exportLatexCode && (
                  <div>Use "Show TeX" to inspect the generated table source.</div>
                )}
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>

      <TableMutateDrawer
        open={showDrawer}
        onOpenChange={handleDrawerChange}
        onSuccess={handleSuccess}
        benchmark={benchmark}
        initialValues={tableFormSelections ?? undefined}
        onSelectionsChange={(v) => setTableFormSelections(v)}
      />

      {kmBugId && (
        <KaplanMeier
          open={kmOpen}
          onOpenChange={(v: boolean) => {
            setKmOpen(v);
            if (!v) setKmMetric("detected");
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
