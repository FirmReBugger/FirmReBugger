import { useEffect, useMemo, useState } from "react";
import { useTheme } from "next-themes";
import { VegaLite, type VisualizationSpec, type View } from "react-vega";
import { useApiUrl } from "@/context/api-url-context";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import { Activity, Download } from "lucide-react";
import { toast } from "sonner";

// Mirrors the shadcn chart tokens in src/styles/theme.css so the graph
// matches the app's palette without a DOM read on every theme toggle.
const CHART_COLORS = {
  light: {
    line: "oklch(0.646 0.222 41.116)",
    grid: "oklch(0.929 0.013 255.508)",
    muted: "oklch(0.554 0.046 257.417)",
    surface: "oklch(1 0 0)",
  },
  dark: {
    line: "oklch(0.488 0.243 264.376)",
    grid: "oklch(1 0 0 / 10%)",
    muted: "oklch(0.704 0.04 256.788)",
    surface: "oklch(0.208 0.042 265.755)",
  },
};

interface CoverageBucket {
  elapsed_seconds: number;
  mean_blocks: number;
  min_blocks: number;
  max_blocks: number;
  mean_pct: number | null;
  min_pct: number | null;
  max_pct: number | null;
  num_runs: number;
}

interface CoverageTimeseriesResponse {
  buckets: CoverageBucket[];
  total_blocks: number | null;
  runs_included: number[];
}

interface CoverageGraphDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  jobId: string | null;
  runNumbers: number[];
  title?: string | null;
}

export function CoverageGraphDialog({
  open,
  onOpenChange,
  jobId,
  runNumbers,
  title,
}: CoverageGraphDialogProps) {
  const API_URL = useApiUrl();
  const { resolvedTheme } = useTheme();
  const [selectedRuns, setSelectedRuns] = useState<Set<number>>(new Set());
  const [data, setData] = useState<CoverageTimeseriesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<View | null>(null);

  // Default to every run selected each time the dialog is opened for a job.
  useEffect(() => {
    if (open) {
      setSelectedRuns(new Set(runNumbers));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, jobId]);

  useEffect(() => {
    if (!open || !jobId || selectedRuns.size === 0) {
      setData(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    const runs = Array.from(selectedRuns).sort((a, b) => a - b).join(",");
    fetch(
      `${API_URL}/api/jobs/${jobId}/coverage-timeseries?runs=${runs}`,
    )
      .then((res) => res.json())
      .then((json: CoverageTimeseriesResponse) => {
        if (!cancelled) setData(json);
      })
      .catch((err) => {
        console.error("Failed to fetch coverage timeseries:", err);
        if (!cancelled) setError("Failed to load coverage data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, jobId, selectedRuns, API_URL]);

  const allSelected =
    runNumbers.length > 0 && selectedRuns.size === runNumbers.length;
  const someSelected = selectedRuns.size > 0 && !allSelected;

  const toggleRun = (runNumber: number, checked: boolean) => {
    setSelectedRuns((prev) => {
      const next = new Set(prev);
      if (checked) next.add(runNumber);
      else next.delete(runNumber);
      return next;
    });
  };

  const toggleAll = (checked: boolean) => {
    setSelectedRuns(checked ? new Set(runNumbers) : new Set());
  };

  const handleExport = async () => {
    if (!view) return;
    try {
      const url = await view.toImageURL("png", 2);
      const a = document.createElement("a");
      a.href = url;
      a.download = `coverage-${jobId ?? "graph"}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      toast.success("Coverage graph exported");
    } catch (err) {
      console.error("Failed to export coverage graph:", err);
      toast.error("Failed to export coverage graph");
    }
  };

  const colors = CHART_COLORS[resolvedTheme === "dark" ? "dark" : "light"];

  const { spec, chartData, unitLabel } = useMemo(() => {
    const buckets = data?.buckets ?? [];
    const maxSeconds = buckets.length
      ? buckets[buckets.length - 1].elapsed_seconds
      : 0;
    const useHours = maxSeconds >= 3600;
    const divisor = useHours ? 3600 : 60;
    const label = useHours ? "Elapsed time (hours)" : "Elapsed time (minutes)";

    const values = buckets.map((b) => ({
      t: b.elapsed_seconds / divisor,
      mean: b.mean_blocks,
      min: b.min_blocks,
      max: b.max_blocks,
      meanPct: b.mean_pct,
      numRuns: b.num_runs,
    }));

    const yTitle = data?.total_blocks ? "Basic blocks covered" : "Blocks covered";

    const vegaSpec: VisualizationSpec = {
      $schema: "https://vega.github.io/schema/vega-lite/v5.json",
      width: "container",
      height: "container",
      autosize: { type: "fit", contains: "padding" },
      background: "transparent",
      data: { name: "coverage" },
      layer: [
        {
          mark: {
            type: "area",
            opacity: 0.12,
            color: colors.line,
            interpolate: "monotone",
          },
          encoding: {
            x: { field: "t", type: "quantitative", title: label },
            y: { field: "min", type: "quantitative", title: yTitle },
            y2: { field: "max" },
          },
        },
        {
          mark: {
            type: "line",
            strokeWidth: 2,
            color: colors.line,
            interpolate: "monotone",
          },
          encoding: {
            x: { field: "t", type: "quantitative" },
            y: { field: "mean", type: "quantitative" },
          },
        },
        {
          params: [
            {
              name: "hover",
              select: {
                type: "point",
                fields: ["t"],
                nearest: true,
                on: "pointerover",
                clear: "pointerout",
              },
            },
          ],
          mark: { type: "point", opacity: 0 },
          encoding: {
            x: { field: "t", type: "quantitative" },
            y: { field: "mean", type: "quantitative" },
            tooltip: [
              { field: "t", type: "quantitative", title: label, format: ",.2f" },
              { field: "mean", type: "quantitative", title: "Mean blocks", format: ",.0f" },
              { field: "min", type: "quantitative", title: "Min blocks", format: ",.0f" },
              { field: "max", type: "quantitative", title: "Max blocks", format: ",.0f" },
              ...(data?.total_blocks
                ? [{ field: "meanPct", type: "quantitative" as const, title: "Mean coverage %" }]
                : []),
              { field: "numRuns", type: "quantitative", title: "Runs sampled" },
            ],
          },
        },
        {
          transform: [{ filter: { param: "hover", empty: false } }],
          mark: { type: "rule", color: colors.grid, strokeWidth: 1 },
          encoding: { x: { field: "t", type: "quantitative" } },
        },
        {
          transform: [{ filter: { param: "hover", empty: false } }],
          mark: {
            type: "point",
            size: 90,
            filled: true,
            color: colors.line,
            stroke: colors.surface,
            strokeWidth: 2,
          },
          encoding: {
            x: { field: "t", type: "quantitative" },
            y: { field: "mean", type: "quantitative" },
          },
        },
      ],
      config: {
        view: { stroke: "transparent" },
        axis: {
          grid: true,
          gridColor: colors.grid,
          domain: false,
          tickColor: colors.grid,
          labelColor: colors.muted,
          titleColor: colors.muted,
          labelFont: "inherit",
          titleFont: "inherit",
        },
      },
    };

    return { spec: vegaSpec, chartData: values, unitLabel: label };
  }, [data, colors]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="!w-[95vw] !max-w-[1200px] h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary" />
            {title || "Coverage Graph"}
          </DialogTitle>
          <DialogDescription>
            Average basic-block coverage over time across the selected runs
            (shaded band shows the min/max spread).
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-1 min-h-0 gap-4">
          <div className="w-[160px] shrink-0 flex flex-col border rounded-md">
            <div className="flex items-center gap-2 p-3 border-b">
              <Checkbox
                checked={allSelected ? true : someSelected ? "indeterminate" : false}
                onCheckedChange={(checked) => toggleAll(checked === true)}
              />
              <span className="text-xs font-semibold">Select all</span>
            </div>
            <ScrollArea className="flex-1">
              <div className="p-3 space-y-2">
                {runNumbers.map((runNumber) => (
                  <label
                    key={runNumber}
                    className="flex items-center gap-2 text-xs font-mono cursor-pointer"
                  >
                    <Checkbox
                      checked={selectedRuns.has(runNumber)}
                      onCheckedChange={(checked) =>
                        toggleRun(runNumber, checked === true)
                      }
                    />
                    Run #{runNumber}
                  </label>
                ))}
              </div>
            </ScrollArea>
          </div>

          <Separator orientation="vertical" />

          <div className="flex-1 min-w-0 flex flex-col">
            {selectedRuns.size === 0 ? (
              <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground">
                Select at least one run to plot coverage.
              </div>
            ) : loading && !data ? (
              <div className="flex-1 flex items-center justify-center gap-2 text-sm text-muted-foreground">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary" />
                Loading coverage data...
              </div>
            ) : error ? (
              <div className="flex-1 flex items-center justify-center text-sm text-destructive">
                {error}
              </div>
            ) : !data || data.buckets.length === 0 ? (
              <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground">
                No coverage data yet for the selected runs.
              </div>
            ) : (
              <>
                <div className="flex justify-end pb-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-xs"
                    onClick={handleExport}
                    disabled={!view}
                  >
                    <Download className="h-3.5 w-3.5 mr-1.5" />
                    Export PNG
                  </Button>
                </div>
                <div className="flex-1 min-h-0">
                  <VegaLite
                    spec={spec}
                    data={{ coverage: chartData }}
                    actions={false}
                    renderer="svg"
                    onNewView={setView}
                    style={{ width: "100%", height: "100%" }}
                  />
                </div>
                <p className="text-xs text-muted-foreground text-center pt-1">
                  {unitLabel} &middot; {data.runs_included.length} run
                  {data.runs_included.length === 1 ? "" : "s"} averaged
                  {data.total_blocks
                    ? ` · ${data.total_blocks.toLocaleString()} total valid blocks`
                    : ""}
                </p>
              </>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
