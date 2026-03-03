import { useState, useEffect, useRef } from "react";
import { UpSetJS } from "@upsetjs/react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface UpSetPlotProps {
  benchmark: string;
  tableData?: any;
}

export function UpSetPlot({ benchmark, tableData }: UpSetPlotProps) {
  const [processedMap, setProcessedMap] = useState<Record<string, any>>({
    reached: null,
    triggered: null,
    detected: null,
  });
  const [currentMetric, setCurrentMetric] = useState<
    "reached" | "triggered" | "detected"
  >("reached");
  const [selection, setSelection] = useState<any>(null);
  const [hoveredSetName, setHoveredSetName] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(
    null,
  );
  const [hoveredIntersection, setHoveredIntersection] = useState<{
    fp: number;
    tp: number;
    total: number;
  } | null>(null);
  const [intersectionTooltipPos, setIntersectionTooltipPos] = useState<{
    x: number;
    y: number;
  } | null>(null);
  const [dimensions, setDimensions] = useState({ width: 1200, height: 600 });
  const [detailsOpen, setDetailsOpen] = useState(false);
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

  const truncateSetName = (name: string, maxLength: number = 12): string => {
    if (name.length <= maxLength) return name;
    return name.substring(0, maxLength) + "...";
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

            if (hasMetric) {
              memberSets.push(fuzzer);
            }
          },
        );

        const bugName = `${binary}:${bugId}`;
        const isFP = bugId.startsWith("FP_");

        if (memberSets.length === 0) {
          missedBugs++;
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
      .sort((a, b) => a[0].localeCompare(b[0]))
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

  const openSelectionDetails = () => {
    if (!selection) return;
    if (
      selection?.type !== "intersection" &&
      selection?.type !== "distinctIntersection"
    ) {
      return;
    }

    const elems = processedMap[currentMetric]?.elems || [];
    const selectedElems: string[] = selection?.elems || [];

    const tp: string[] = [];
    const fp: string[] = [];

    selectedElems.forEach((elemName) => {
      const elem = elems.find((e: any) => e.name === elemName);
      if (!elem) return;
      const bugName = String(elem.name || "").split(":").slice(1).join(":") || String(elem.name || "");
      if (elem.isFP) {
        fp.push(bugName);
      } else {
        tp.push(bugName);
      }
    });

    setSelectedIntersectionBugs({
      tp: tp.sort((a, b) => a.localeCompare(b)),
      fp: fp.sort((a, b) => a.localeCompare(b)),
    });
    setDetailsOpen(true);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Bug UpSet Plot - {benchmark}</CardTitle>
            <CardDescription>
              Interactive UpSet plot for bugs (
              {currentMetric} metric). You can click on the plot to view details about the bugs in the selected intersection.
              {processedMap[currentMetric]?.stats && (
                <span className="block mt-1">
                  {processedMap[currentMetric].stats.hitBugs} of{" "}
                  {processedMap[currentMetric].stats.totalBugs} bugs{" "}
                  {currentMetric}
                </span>
              )}
            </CardDescription>
          </div>
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
      </CardHeader>
      <CardContent>
        <div ref={containerRef} className="w-full relative">
          {processedMap[currentMetric] &&
          processedMap[currentMetric].elems?.length > 0 ? (
            <div
              className="relative"
              style={{ height: `${dimensions.height}px` }}
            >
              <div
                onClickCapture={(e) => {
                  const target = e.target as HTMLElement;
                  if (target.closest("rect")) {
                    openSelectionDetails();
                  }
                }}
                onMouseMove={(e) => {
                  const target = e.target as HTMLElement;

                  // Check for text elements (fuzzer names)
                  const textElement = target.closest("text");
                  if (textElement) {
                    const textContent = textElement.textContent || "";
                    const set = processedMap[currentMetric].sets?.find(
                      (s: any) =>
                        truncateSetName(
                          s.displayName || s.fullName || s.name,
                        ) === textContent,
                    );
                    if (set && set.displayName && set.displayName.length > 12) {
                      setHoveredSetName(set.displayName);
                      setTooltipPos({ x: e.clientX, y: e.clientY });
                    } else {
                      setHoveredSetName(null);
                      setTooltipPos(null);
                    }
                  }

                  const rectElement = target.closest("rect");
                  if (
                    rectElement &&
                    (selection?.type === "intersection" ||
                      selection?.type === "distinctIntersection")
                  ) {
                    const elems = processedMap[currentMetric].elems || [];
                    const selectedElems = selection.elems || [];

                    let fpCount = 0;
                    let tpCount = 0;

                    selectedElems.forEach((elemName: string) => {
                      const elem = elems.find((e: any) => e.name === elemName);
                      if (elem) {
                        if (elem.isFP) {
                          fpCount++;
                        } else {
                          tpCount++;
                        }
                      }
                    });

                    setHoveredIntersection({
                      fp: fpCount,
                      tp: tpCount,
                      total: fpCount + tpCount,
                    });
                    setIntersectionTooltipPos({ x: e.clientX, y: e.clientY });
                  } else if (!rectElement) {
                    setHoveredIntersection(null);
                    setIntersectionTooltipPos(null);
                  }
                }}
                onMouseLeave={() => {
                  setHoveredSetName(null);
                  setTooltipPos(null);
                  setHoveredIntersection(null);
                  setIntersectionTooltipPos(null);
                }}
              >
                <UpSetComponent
                  {...(processedMap[currentMetric] as any)}
                  combinations={{
                    type: "distinctIntersection",
                    order: ["cardinality:desc", "name:asc"],
                  }}
                  width={dimensions.width}
                  height={dimensions.height}
                  selection={selection}
                  onHover={setSelection}
                  theme="vega"
                  exportButtons={false}
                  tooltips={false}
                />
              </div>

              {/* Tooltip for full fuzzer name */}
              {hoveredSetName && tooltipPos && (
                <div
                  className="fixed z-50 px-3 py-2 text-sm bg-popover text-popover-foreground border rounded-md shadow-md pointer-events-none"
                  style={{
                    left: `${tooltipPos.x + 10}px`,
                    top: `${tooltipPos.y - 30}px`,
                  }}
                >
                  {hoveredSetName}
                </div>
              )}

              {/* Tooltip for FP/TP breakdown */}
              {hoveredIntersection && intersectionTooltipPos && (
                <div
                  className="fixed z-50 px-3 py-2 text-sm bg-popover text-popover-foreground border rounded-md shadow-md pointer-events-none"
                  style={{
                    left: `${intersectionTooltipPos.x + 10}px`,
                    top: `${intersectionTooltipPos.y - 50}px`,
                  }}
                >
                  <div className="font-semibold mb-1">
                    Total: {hoveredIntersection.total}
                  </div>
                  <div className="text-green-600 dark:text-green-400">
                    TP: {hoveredIntersection.tp}
                  </div>
                  <div className="text-red-600 dark:text-red-400">
                    FP: {hoveredIntersection.fp}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-muted-foreground p-6 text-center">
              {tableData
                ? `No bugs with ${currentMetric} data available. This means no fuzzer ${currentMetric === "reached" ? "reached" : currentMetric === "triggered" ? "triggered" : "detected"} any bugs for this metric.`
                : "Configure the bug table above to generate an upset plot."}
            </div>
          )}
        </div>
      </CardContent>

      <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {currentMetric.charAt(0).toUpperCase() + currentMetric.slice(1)} bugs in selection
            </DialogTitle>
            <DialogDescription>
              {selectedIntersectionBugs.tp.length + selectedIntersectionBugs.fp.length} total · {selectedIntersectionBugs.tp.length} true positive · {selectedIntersectionBugs.fp.length} false positive
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <div className="text-sm font-semibold text-green-600 dark:text-green-400 mb-1">
                True Positive Bugs
              </div>
              {selectedIntersectionBugs.tp.length > 0 ? (
                <div className="text-sm space-y-1">
                  {selectedIntersectionBugs.tp.map((bugId) => (
                    <div key={`tp-${bugId}`} className="font-mono">
                      {bugId}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">None</div>
              )}
            </div>

            <div>
              <div className="text-sm font-semibold text-red-600 dark:text-red-400 mb-1">
                False Positive Bugs
              </div>
              {selectedIntersectionBugs.fp.length > 0 ? (
                <div className="text-sm space-y-1">
                  {selectedIntersectionBugs.fp.map((bugId) => (
                    <div key={`fp-${bugId}`} className="font-mono">
                      {bugId}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">None</div>
              )}
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
