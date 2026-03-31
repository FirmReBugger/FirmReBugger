import { useState, useEffect, useMemo, useRef } from "react";
import { UpSetJS } from "@upsetjs/react";
import { generateCombinations } from "@upsetjs/model";
import { ChevronLeft, ChevronRight, Download, X } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScrollArea as _ScrollArea } from "@/components/ui/scroll-area"; // kept for potential future use
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
  const [exportLoading, setExportLoading] = useState(false);
  const [selectionNameTooltip, setSelectionNameTooltip] = useState<{
    x: number; y: number; text: string;
  } | null>(null);

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
    const onDocClick = (e: MouseEvent) => {
      if (containerRef.current && containerRef.current.contains(e.target as Node)) return;
      setSelection(null);
    };

    document.addEventListener("click", onDocClick);
    return () => {
      document.removeEventListener("click", onDocClick);
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
    const allItems = processedMap[currentMetric]?.elems || [];
    const currentSets = processedMap[currentMetric]?.sets || [];

    // First: try to match to one of our fuzzer sets by displayName/name.
    // This is the reliable path for set-bar clicks regardless of what UpSetJS
    // puts in selection.type or selection.elems.
    const selName = String(activeSelection?.displayName ?? activeSelection?.name ?? "");
    const matchedSet = currentSets.find((s: any) =>
      String(s.displayName ?? s.name ?? "") === selName
    );

    let selectedElemNames: string[];
    if (matchedSet) {
      // Use our own stored elems array — guaranteed to contain "binary:bugId" strings
      selectedElemNames = Array.isArray(matchedSet.elems) ? [...matchedSet.elems] : [];
    } else {
      // Intersection click: UpSetJS passes elems as the intersection members
      const rawElems = activeSelection?.elems;
      selectedElemNames = rawElems
        ? Array.isArray(rawElems) ? [...rawElems] : Array.from(rawElems as Iterable<string>)
        : [];
    }

    const tp: string[] = [];
    const fp: string[] = [];

    selectedElemNames.forEach((elemName: string) => {
      const item = allItems.find((e: any) => e.name === elemName);
      if (!item) return;
      const bugName =
        String(item.name || "")
          .split(":")
          .slice(1)
          .join(":") || String(item.name || "");
      if (item.isFP) {
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

  const panelData = useMemo(() => {
    if (!selection) return null;
    // No type guard — handle set bar clicks and intersection clicks uniformly
    return classifySelectionBugs(selection);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selection, processedMap, currentMetric]);

  useEffect(() => {
    if (panelData) {
      setSelectedIntersectionBugs(panelData);
    }
  }, [panelData]);

  const fullSelectionName = useMemo(() => {
    if (!selection) return "";
    // Check if this matches a known fuzzer set by displayName/name — fuzzer bar clicks
    const currentSets = processedMap[currentMetric]?.sets || [];
    const selDispName = String(selection?.displayName ?? selection?.name ?? "");
    const isKnownFuzzer = currentSets.some((s: any) =>
      String(s.displayName ?? s.name ?? "") === selDispName
    );
    if (selection?.type === "set" || isKnownFuzzer) {
      return selDispName;
    }
    // Intersection: selection.sets is a JS Set of ISet objects (not strings)
    const rawSets = selection?.sets;
    const setsArray: any[] = rawSets
      ? Array.isArray(rawSets) ? rawSets : Array.from(rawSets as Set<any>)
      : [];
    if (setsArray.length === 0) return String(selection?.name ?? "Selection");
    return setsArray.map((s: any) => String(s.displayName ?? s.name ?? "")).join(" ∩ ");
  }, [selection, processedMap, currentMetric]);

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
              Interactive Upset plot showing the distribution of bugs across fuzzers for {benchmark}, based on the current bug table data.
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportUpSet}
            disabled={exportLoading}
          >
            <Download className="h-4 w-4 mr-2" />
            {exportLoading ? "Exporting..." : "Export"}
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
                    evt?.stopPropagation?.();
                    if (evt?.button === 2) return;
                    if (!nextSelection) return;
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
        <hr className="my-4 border-border" />
        {/* Info area */}
        <div onClick={(e) => e.stopPropagation()}>
          {/* Header: title + counts + optional dismiss */}
          <div className="flex items-center justify-between mb-2 gap-2">
            <div className="min-w-0 flex items-baseline gap-1.5 flex-wrap">
              <span
                className="text-xs font-semibold text-muted-foreground uppercase tracking-wide cursor-default"
                onMouseEnter={(e) => {
                  if (panelData && fullSelectionName.length > 50) {
                    setSelectionNameTooltip({ x: e.clientX, y: e.clientY, text: fullSelectionName });
                  }
                }}
                onMouseMove={(e) => {
                  if (selectionNameTooltip) {
                    setSelectionNameTooltip((prev) => prev ? { ...prev, x: e.clientX, y: e.clientY } : null);
                  }
                }}
                onMouseLeave={() => setSelectionNameTooltip(null)}
              >
                {panelData ? (fullSelectionName || "Selection") : "All bugs"}
              </span>
              <span className="text-[10px] text-muted-foreground capitalize">{currentMetric}</span>
              {panelData && (
                <span className="text-[10px] text-muted-foreground">
                  &middot;&nbsp;{selectedIntersectionBugs.tp.length + selectedIntersectionBugs.fp.length} total
                  &nbsp;&middot;&nbsp;<span className="text-green-600 dark:text-green-400">{selectedIntersectionBugs.tp.length} TP</span>
                  &nbsp;&middot;&nbsp;<span className="text-red-500">{selectedIntersectionBugs.fp.length} FP</span>
                </span>
              )}
            </div>
            {panelData && (
              <button
                className="text-muted-foreground hover:text-foreground shrink-0"
                onClick={(e) => { e.stopPropagation(); setSelection(null); }}
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>

          {/*
            Body: the overview is always rendered (drives the container height).
            When a selection is active it becomes invisible but still occupies space,
            and the detail view is absolutely overlaid on top — zero layout shift.
          */}
          <div className="relative">
            {/* Overview — always in DOM; invisible (but still laid out) when detail active */}
            <div className={panelData ? "invisible pointer-events-none" : ""} aria-hidden={panelData ? "true" : undefined}>
              {(() => {
                const currentSets = processedMap[currentMetric]?.sets || [];
                if (currentSets.length === 0) {
                  return <div className="text-sm text-muted-foreground py-1">No data loaded yet.</div>;
                }
                return (
                  <table className="w-full border-collapse">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left text-xs font-semibold text-muted-foreground uppercase tracking-wide pb-1.5 pr-3 w-[130px]">Fuzzer</th>
                        <th className="text-left text-xs font-semibold text-green-600 dark:text-green-400 uppercase tracking-wide pb-1.5 pr-2">True Positives</th>
                        <th className="text-left text-xs font-semibold text-red-500 uppercase tracking-wide pb-1.5">False Positives</th>
                      </tr>
                    </thead>
                    <tbody>
                      {currentSets.map((set: any) => {
                        const fuzzerName = String(set?.displayName ?? set?.name ?? "");
                        const tpBugs: string[] = [];
                        const fpBugs: string[] = [];
                        (set.elems || []).forEach((elemName: string) => {
                          const info = bugByName.get(String(elemName));
                          const display = String(elemName).split(":").slice(1).join(":") || String(elemName);
                          if (info?.isFP) fpBugs.push(display);
                          else tpBugs.push(display);
                        });
                        return (
                          <tr key={fuzzerName} className="border-b border-border/40">
                            <td className="py-1.5 pr-3 align-middle">
                              <span className="text-sm font-medium text-foreground" title={fuzzerName}>{fuzzerName}</span>
                            </td>
                            <td className="py-1.5 pr-2 align-middle">
                              <div className="flex flex-wrap gap-0.5">
                                {tpBugs.length > 0
                                  ? tpBugs.map((b) => (
                                      <span key={b} className="font-mono text-xs px-1 py-0.5 rounded bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">{b}</span>
                                    ))
                                  : <span className="text-sm text-muted-foreground">—</span>
                                }
                              </div>
                            </td>
                            <td className="py-1.5 align-middle">
                              <div className="flex flex-wrap gap-0.5">
                                {fpBugs.length > 0
                                  ? fpBugs.map((b) => (
                                      <span key={b} className="font-mono text-xs px-1 py-0.5 rounded bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400">{b}</span>
                                    ))
                                  : <span className="text-sm text-muted-foreground">—</span>
                                }
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                );
              })()}
            </div>

            {/* Detail — absolutely overlaid; scrollable if it exceeds the overview height */}
            {panelData && (
              <div className="absolute inset-0 overflow-auto bg-background">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs font-semibold text-green-600 dark:text-green-400 uppercase tracking-wide pb-1.5 pr-2">
                        True Positives ({selectedIntersectionBugs.tp.length})
                      </th>
                      <th className="text-left text-xs font-semibold text-red-500 uppercase tracking-wide pb-1.5">
                        False Positives ({selectedIntersectionBugs.fp.length})
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td className="py-1.5 pr-2 align-middle">
                        {selectedIntersectionBugs.tp.length > 0 ? (
                          <div className="flex flex-wrap gap-0.5">
                            {selectedIntersectionBugs.tp.map((b) => (
                              <span key={`tp-${b}`} className="font-mono text-xs px-1 py-0.5 rounded bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">{b}</span>
                            ))}
                          </div>
                        ) : <span className="text-sm text-muted-foreground">—</span>}
                      </td>
                      <td className="py-1.5 align-middle">
                        {selectedIntersectionBugs.fp.length > 0 ? (
                          <div className="flex flex-wrap gap-0.5">
                            {selectedIntersectionBugs.fp.map((b) => (
                              <span key={`fp-${b}`} className="font-mono text-xs px-1 py-0.5 rounded bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400">{b}</span>
                            ))}
                          </div>
                        ) : <span className="text-sm text-muted-foreground">—</span>}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Footer hint */}
          <div className="mt-2 text-[10px] text-muted-foreground">
            {panelData
              ? "Click outside to dismiss · or click another intersection or fuzzer bar."
              : "Click an intersection for specifics · click a fuzzer bar to filter by fuzzer."}
          </div>
        </div>

        <div className="mt-4 flex items-center justify-center">
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
      {selectionNameTooltip && (
        <div
          className="fixed z-50 bg-popover text-popover-foreground border rounded-lg shadow-lg pointer-events-none"
          style={{
            left: `${selectionNameTooltip.x}px`,
            top: `${selectionNameTooltip.y}px`,
            transform: "translate(-50%, -100%)",
            maxWidth: "340px",
            marginBottom: "6px",
          }}
        >
          <div className="px-3 pt-2 pb-2.5">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">Full name</div>
            <div className="text-xs leading-relaxed break-words">{selectionNameTooltip.text}</div>
          </div>
        </div>
      )}
    </Card>
  );
}
