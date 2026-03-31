import { useState, useEffect, useMemo, useRef } from "react";
import { UpSetJS } from "@upsetjs/react";
import { generateCombinations } from "@upsetjs/model";
import { ChevronLeft, ChevronRight, Download } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";

interface UpSetPlotProps {
  benchmark: string;
  tableData?: any;
  reportPaths?: string[];
}

export function UpSetPlot({
  benchmark,
  tableData,
  reportPaths: _reportPaths = [],
}: UpSetPlotProps) {
  const selectionHighlightColor = "#E3B341";

  const [processedMap, setProcessedMap] = useState<Record<string, any>>({
    reached: null,
    triggered: null,
    detected: null,
  });
  const [currentMetric, setCurrentMetric] = useState<
    "reached" | "triggered" | "detected"
  >("detected");
  const [selection, setSelection] = useState<any>(null);
  const [dimensions, setDimensions] = useState({ width: 1200, height: 600 });
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);

  const [selectedIntersectionBugs, setSelectedIntersectionBugs] = useState<{
    tp: string[];
    fp: string[];
  }>({ tp: [], fp: [] });
  const containerRef = useRef<HTMLDivElement | null>(null);

  const UpSetComponent: any = UpSetJS;
  const metrics: Array<"reached" | "triggered" | "detected"> = [
    "reached",
    "triggered",
    "detected",
  ];
  const metricVerb: Record<"reached" | "triggered" | "detected", string> = {
    reached: "reached",
    triggered: "triggered",
    detected: "detected",
  };

  const truncateSetName = (name: string, maxLength: number = 12): string => {
    if (name.length <= maxLength) return name;
    return name.substring(0, maxLength) + "...";
  };

  const sanitizePatternId = (value: string) =>
    value.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");

  const patternIdForCombination = (set: any) => {
    const name = String(set?.name ?? "combination");
    const safe = sanitizePatternId(name);
    return `tpfp-${currentMetric}-${safe || "combination"}`;
  };

  const patternIdForSet = (set: any) => {
    const name = String(set?.displayName ?? set?.name ?? "set");
    const safe = sanitizePatternId(name);
    return `tpfp-set-${currentMetric}-${safe || "set"}`;
  };

  useEffect(() => {
    if (!containerRef.current) return;

    const updateDimensions = () => {
      if (containerRef.current) {
        const width = containerRef.current.clientWidth - 48; // Account for padding
        const height = Math.max(500, Math.min(700, width * 0.5)); // Maintain aspect ratio
        setDimensions({ width, height });
      }
    };

    const timer = setTimeout(updateDimensions, 10);

    window.addEventListener("resize", updateDimensions);

    const resizeObserver = new ResizeObserver(updateDimensions);
    resizeObserver.observe(containerRef.current);

    return () => {
      clearTimeout(timer);
      window.removeEventListener("resize", updateDimensions);
      resizeObserver.disconnect();
    };
  }, []);

  useEffect(() => {
    const onDocMouseDown = (evt: MouseEvent) => {
      if (!containerRef.current) return;
      if (!containerRef.current.contains(evt.target as Node)) {
        setSelection(null);
      }
    };

    document.addEventListener("mousedown", onDocMouseDown);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
    };
  }, []);

  useEffect(() => {
    if (!selection) {
      setDetailsOpen(false);
    }
  }, [selection]);

  const convertTableToUpset = (
    tableData: any[],
    metric: "reached" | "triggered" | "detected",
  ) => {
    const setsMap = new Map<string, Set<string>>();
    const items: Array<{ name: string; sets: string[]; isFP: boolean }> = [];
    let totalBugs = 0;
    let missedBugs = 0;

    tableData.forEach((binaryEntry: any) => {
      const binary = binaryEntry.binary;
      (binaryEntry.bugs || []).forEach((bug: any) => {
        const bugId = String(bug?.bugId || "");
        if (bugId.toUpperCase().startsWith("ERROR")) {
          return;
        }

        totalBugs++;
        const fuzzerStats = bug.fuzzerStats || {};
        const memberSets: string[] = [];

        Object.entries(fuzzerStats).forEach(
          ([fuzzer, stats]: [string, any]) => {
            if (!setsMap.has(fuzzer)) {
              setsMap.set(fuzzer, new Set<string>());
            }

            const runs = stats?.runs || [];
            const hasMetric = runs.some((r: any) => r[metric] != null);

                // Standard UpSet membership: dot present means this fuzzer hit the bug.
                if (hasMetric) {
              memberSets.push(fuzzer);
            }
          },
        );

        const bugName = `${binary}:${bugId}`;
        const isFP = bugId.startsWith("FP_");

        if (memberSets.length === 0) {
          missedBugs++;
          items.push({
            name: bugName,
            sets: [],
            isFP,
          });
          return;
        }

        items.push({
          name: bugName,
          sets: memberSets,
          isFP,
        });

        memberSets.forEach((fuzzer) => {
          setsMap.get(fuzzer)?.add(bugName);
        });
      });
    });

    const sets = Array.from(setsMap.entries())
      .sort((a, b) => {
        const bySize = b[1].size - a[1].size;
        if (bySize !== 0) return bySize;
        return a[0].localeCompare(b[0]);
      })
      .map(([name, elemsSet]) => ({
        name,
        cardinality: elemsSet.size,
        sets: elemsSet,
        elems: Array.from(elemsSet),
        fullName: name, // Store full name for tooltip
      }));

    return {
      sets,
      elems: items,
      stats: {
        totalBugs,
        missedBugs,
        hitBugs: totalBugs - missedBugs,
      },
    };
  };

  useEffect(() => {
    if (tableData && Array.isArray(tableData)) {
      try {
        console.log("UpSetPlot processing tableData:", tableData);
        const results = {
          reached: convertTableToUpset(tableData, "reached"),
          triggered: convertTableToUpset(tableData, "triggered"),
          detected: convertTableToUpset(tableData, "detected"),
        };
        console.log("UpSetPlot processed results:", results);

        Object.keys(results).forEach((metric) => {
          const data = results[metric as keyof typeof results];
          if (data && data.sets) {
            data.sets = data.sets.map((set: any) => ({
              ...set,
              displayName: set.name,
              name: truncateSetName(set.name),
            }));
          }
        });

        setProcessedMap(results);
      } catch (e) {
        console.error("Error processing upset data:", e);
      }
    }
  }, [tableData]);

  const visibleCombinations = useMemo(() => {
    const current = processedMap[currentMetric];
    if (!current?.sets || !Array.isArray(current.sets)) {
      return [];
    }

    const universe = (current.elems || []).map((e: any) => e.name);

    const generated = generateCombinations(current.sets as any, {
      type: "distinctIntersection",
      min: 0,
      empty: true,
      elems: universe,
      toElemKey: (v: string) => v,
      order: ["degree:asc", "cardinality:desc", "name:asc"],
    } as any);

    // Keep all intersections with bugs plus exactly one empty intersection.
    return (generated || [])
      .filter(
      (c: any) => c.cardinality > 0 || c.degree === 0,
      )
      .map((c: any) => ({
        ...c,
        color: `url(#${patternIdForCombination(c)})`,
      }));
  }, [processedMap, currentMetric]);

  const bugByName = useMemo(() => {
    const m = new Map<string, { isFP: boolean }>();
    (processedMap[currentMetric]?.elems || []).forEach((e: any) => {
      m.set(String(e.name), { isFP: Boolean(e.isFP) });
    });
    return m;
  }, [processedMap, currentMetric]);

  const tpFpByCombination = useMemo(() => {
    const counts = new Map<string, { tp: number; fp: number }>();

    (visibleCombinations || []).forEach((set: any) => {
      const elems: string[] = set?.elems || [];
      let tp = 0;
      let fp = 0;
      elems.forEach((name) => {
        const info = bugByName.get(String(name));
        if (!info) return;
        if (info.isFP) fp += 1;
        else tp += 1;
      });
      counts.set(String(set?.name ?? ""), { tp, fp });
    });

    return counts;
  }, [visibleCombinations, bugByName]);

  const tpFpBySet = useMemo(() => {
    const currentSets = processedMap[currentMetric]?.sets || [];
    const counts = new Map<string, { tp: number; fp: number }>();

    currentSets.forEach((set: any) => {
      const elems: string[] = set?.elems || [];
      let tp = 0;
      let fp = 0;
      elems.forEach((name) => {
        const info = bugByName.get(String(name));
        if (!info) return;
        if (info.isFP) fp += 1;
        else tp += 1;
      });
      counts.set(String(set?.displayName ?? set?.name ?? ""), { tp, fp });
    });

    return counts;
  }, [processedMap, currentMetric, bugByName]);

  const setPatternSpecs = useMemo(() => {
    const currentSets = processedMap[currentMetric]?.sets || [];
    return currentSets.map((set: any, idx: number) => {
      const key = String(set?.displayName ?? set?.name ?? "");
      const counts = tpFpBySet.get(key) || { tp: 0, fp: 0 };
      const total = counts.tp + counts.fp;
      const tpRatio = total > 0 ? counts.tp / total : 0;
      const fpRatio = total > 0 ? counts.fp / total : 0;

      return {
        index: idx + 1,
        id: patternIdForSet(set),
        tpRatio,
        fpRatio,
      };
    });
  }, [processedMap, currentMetric, tpFpBySet]);

  const classifySelectionBugs = (activeSelection: any) => {
    const elems = processedMap[currentMetric]?.elems || [];
    const selectedElems: string[] = activeSelection?.elems || [];

    const tp: string[] = [];
    const fp: string[] = [];

    selectedElems.forEach((elemName) => {
      const elem = elems.find((e: any) => e.name === elemName);
      if (!elem) return;
      const bugName =
        String(elem.name || "")
          .split(":")
          .slice(1)
          .join(":") || String(elem.name || "");
      if (elem.isFP) {
        fp.push(bugName);
      } else {
        tp.push(bugName);
      }
    });

    return {
      tp: tp.sort((a, b) => a.localeCompare(b)),
      fp: fp.sort((a, b) => a.localeCompare(b)),
    };
  };

  const openSelectionDetails = (selectionOverride?: any) => {
    const activeSelection =
      selectionOverride !== undefined ? selectionOverride : selection;
    if (!activeSelection) return;
    if (
      activeSelection?.type !== "intersection" &&
      activeSelection?.type !== "distinctIntersection" &&
      activeSelection?.type !== "composite"
    ) {
      return;
    }

    setSelectedIntersectionBugs(classifySelectionBugs(activeSelection));
    setDetailsOpen(true);
  };

  const handleExportUpSet = async () => {
    setExportLoading(true);
    try {
      const svg = containerRef.current?.querySelector("svg");
      if (!svg) {
        throw new Error("No UpSet chart available to export");
      }

      const rect = svg.getBoundingClientRect();
      const width = Math.max(1, Math.floor(rect.width));
      const height = Math.max(1, Math.floor(rect.height));

      const svgClone = svg.cloneNode(true) as SVGSVGElement;
      svgClone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
      svgClone.setAttribute("width", String(width));
      svgClone.setAttribute("height", String(height));

      const svgData = new XMLSerializer().serializeToString(svgClone);
      const svgBlob = new Blob([svgData], {
        type: "image/svg+xml;charset=utf-8",
      });
      const svgUrl = URL.createObjectURL(svgBlob);

      const image = new Image();
      await new Promise<void>((resolve, reject) => {
        image.onload = () => resolve();
        image.onerror = () =>
          reject(new Error("Unable to render current UpSet graph for export"));
        image.src = svgUrl;
      });

      const scale = 2;
      const canvas = document.createElement("canvas");
      canvas.width = Math.floor(width * scale);
      canvas.height = Math.floor(height * scale);

      const ctx = canvas.getContext("2d");
      if (!ctx) {
        URL.revokeObjectURL(svgUrl);
        throw new Error("Unable to initialize export canvas");
      }

      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(svgUrl);

      const pngData = canvas.toDataURL("image/png");
      const { jsPDF } = await import("jspdf");
      const pdf = new jsPDF({
        orientation: canvas.width >= canvas.height ? "landscape" : "portrait",
        unit: "pt",
        format: [canvas.width, canvas.height],
      });

      pdf.addImage(pngData, "PNG", 0, 0, canvas.width, canvas.height);
      pdf.save(`${benchmark.toLowerCase()}_${currentMetric}_upset_plot.pdf`);
      toast.success("UpSet PDF downloaded from current view");
    } catch (err) {
      toast.error(
        err instanceof Error
          ? err.message
          : "Failed to export current UpSet graph",
      );
    } finally {
      setExportLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Bug UpSet Plot</CardTitle>
           <CardDescription>
              Right click on the intersection to view details about the bugs {metricVerb[currentMetric]} by the selected fuzzers. Left click to highlight the intersection.
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportUpSet}
            disabled={exportLoading}
          >
            <Download className="h-4 w-4 mr-2" />
            {exportLoading ? "Exporting..." : "Export Current View"}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div ref={containerRef} className="w-full relative">
          {processedMap[currentMetric] &&
          processedMap[currentMetric].elems?.length > 0 ? (
            <div
              className="relative"
              style={{ height: `${dimensions.height}px` }}
            >
              <div className="upset-plot-inner [&_rect]:cursor-pointer [&_circle]:cursor-pointer">
                <style>
                  {`
                    ${setPatternSpecs
                      .map(
                        (s: { id: string; index: number }) => `
                    .upset-plot-inner [data-upset="sets"] > g:nth-child(${s.index}) rect[class*="fillPrimary-"] {
                      fill: url(#${s.id}) !important;
                    }
                    .upset-plot-inner [data-upset="sets"] > g:nth-child(${s.index}) rect[class*="fillOverflow"] {
                      fill: url(#${s.id}) !important;
                    }
                    `,
                      )
                      .join("\n")}
                  `}
                </style>
                <UpSetComponent
                  {...(processedMap[currentMetric] as any)}
                  combinations={visibleCombinations as any}
                  width={dimensions.width}
                  height={dimensions.height}
                  selectionColor={selectionHighlightColor}
                  selection={selection}
                  onClick={(nextSelection: any, evt: any) => {
                    if (evt?.button === 2) return;
                    if (!nextSelection) return;
                    openSelectionDetails(nextSelection);
                  }}
                  onContextMenu={(nextSelection: any, evt: any) => {
                    evt?.preventDefault?.();
                    setSelection(nextSelection);
                  }}
                  setChildrenFactory={(set: any) => {
                    const id = patternIdForSet(set);
                    const key = String(set?.displayName ?? set?.name ?? "");
                    const counts = tpFpBySet.get(key) || { tp: 0, fp: 0 };
                    const total = counts.tp + counts.fp;
                    const tpRatio = total > 0 ? counts.tp / total : 0;
                    const fpRatio = total > 0 ? counts.fp / total : 0;

                    return (
                      <defs>
                        <pattern
                          id={id}
                          patternUnits="objectBoundingBox"
                          patternContentUnits="objectBoundingBox"
                          width={1}
                          height={1}
                        >
                          {tpRatio > 0 && (
                            <rect x={0} y={0} width={tpRatio} height={1} fill="#4e79a7" />
                          )}
                          {fpRatio > 0 && (
                            <rect x={tpRatio} y={0} width={fpRatio} height={1} fill="#c46464" />
                          )}
                        </pattern>
                      </defs>
                    );
                  }}
                  combinationChildrenFactory={(set: any) => {
                    const key = String(set?.name ?? "");
                    const counts = tpFpByCombination.get(key) || { tp: 0, fp: 0 };
                    const total = counts.tp + counts.fp;
                    const tpRatio = total > 0 ? counts.tp / total : 0;
                    const fpRatio = total > 0 ? counts.fp / total : 0;
                    const patternId = patternIdForCombination(set);

                    return (
                      <defs>
                        <pattern
                          id={patternId}
                          patternUnits="objectBoundingBox"
                          patternContentUnits="objectBoundingBox"
                          width={1}
                          height={1}
                        >
                          {tpRatio > 0 && (
                            <rect x={0} y={0} width={1} height={tpRatio} fill="#4e79a7" />
                          )}
                          {fpRatio > 0 && (
                            <rect x={0} y={tpRatio} width={1} height={fpRatio} fill="#c46464" />
                          )}
                        </pattern>
                      </defs>
                    );
                  }}
                  setName={`Total Bugs (${processedMap[currentMetric]?.stats?.totalBugs ?? 0})`}
                  combinationName="Intersection Size"
                  theme="vega"
                  exportButtons={false}
                  tooltips={false}
                />
              </div>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground p-6 text-center">
              {tableData
                ? `No bugs available for hit combinations in ${currentMetric} metric.`
                : "Configure the bug table above to generate an upset plot."}
            </div>
          )}
        </div>
        <div className="mt-3 flex items-center justify-center">
          <div className="flex items-center gap-2">
            <button
              className="px-2 py-1 rounded-md border hover:bg-muted"
              onClick={() =>
                setCurrentMetric((prev) => {
                  const idx = metrics.indexOf(prev);
                  const prevIdx = (idx - 1 + metrics.length) % metrics.length;
                  return metrics[prevIdx];
                })
              }
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <div className="text-sm font-medium capitalize">
              {currentMetric}
            </div>
            <button
              className="px-2 py-1 rounded-md border hover:bg-muted"
              onClick={() =>
                setCurrentMetric((prev) => {
                  const idx = metrics.indexOf(prev);
                  const nextIdx = (idx + 1) % metrics.length;
                  return metrics[nextIdx];
                })
              }
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </CardContent>

      <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle>
              {currentMetric.charAt(0).toUpperCase() + currentMetric.slice(1)}{" "}
              bugs in selection
            </DialogTitle>
            <DialogDescription>
              {selectedIntersectionBugs.tp.length +
                selectedIntersectionBugs.fp.length}{" "}
              total · {selectedIntersectionBugs.tp.length} true positive ·{" "}
              {selectedIntersectionBugs.fp.length} false positive
            </DialogDescription>
          </DialogHeader>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 flex-1 min-h-0">
            <div className="rounded-md border p-3 min-h-0 flex flex-col">
              <div className="text-sm font-semibold text-green-600 dark:text-green-400 mb-2">
                True Positive Bugs ({selectedIntersectionBugs.tp.length})
              </div>
              <ScrollArea className="flex-1 min-h-0 pr-2">
                {selectedIntersectionBugs.tp.length > 0 ? (
                  <div className="space-y-1">
                    {selectedIntersectionBugs.tp.map((bugId) => (
                      <div
                        key={`tp-${bugId}`}
                        className="font-mono text-xs rounded bg-muted/50 px-2 py-1"
                      >
                        {bugId}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground">None</div>
                )}
              </ScrollArea>
            </div>

            <div className="rounded-md border p-3 min-h-0 flex flex-col">
              <div className="text-sm font-semibold text-red-600 dark:text-red-400 mb-2">
                False Positive Bugs ({selectedIntersectionBugs.fp.length})
              </div>
              <ScrollArea className="flex-1 min-h-0 pr-2">
                {selectedIntersectionBugs.fp.length > 0 ? (
                  <div className="space-y-1">
                    {selectedIntersectionBugs.fp.map((bugId) => (
                      <div
                        key={`fp-${bugId}`}
                        className="font-mono text-xs rounded bg-muted/50 px-2 py-1"
                      >
                        {bugId}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground">None</div>
                )}
              </ScrollArea>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
