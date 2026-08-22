import { useEffect, useState, useCallback, Fragment } from "react";
import { useApiUrl } from "@/context/api-url-context";
import { getRouteApi } from "@tanstack/react-router";
import {
  type ExpandedState,
  type SortingState,
  type VisibilityState,
  flexRender,
  getCoreRowModel,
  getExpandedRowModel,
  getFacetedRowModel,
  getFacetedUniqueValues,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { CircleStop, ListChecks, Plus } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTableUrlState } from "@/hooks/use-table-url-state";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DataTableToolbar } from "@/components/data-table";
import { type Task } from "../data/schema";
import {
  tasksColumns as columns,
  setTaskCallbacks,
  getSortableColumns,
} from "./tasks-columns";
import { useTasks } from "./tasks-provider";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import { TaskLogsDialog } from "./task-logs-dialog";
import { CoverageGraphDialog } from "./coverage-graph-dialog";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FolderOutput, Activity, Hash } from "lucide-react";

const route = getRouteApi("/_authenticated/manager/");

type DataTableProps = {
  data: Task[];
  showCreateButton?: boolean;
  enableColumnSorting?: boolean;
  allTasks?: Task[];
  isFinishedJobs?: boolean;
  toolbarExtras?: React.ReactNode;
};

export function TasksTable({
  data,
  showCreateButton = true,
  enableColumnSorting = false,
  allTasks,
  isFinishedJobs = false,
  toolbarExtras,
}: DataTableProps) {
  // Local UI-only states
  const [sorting, setSorting] = useState<SortingState>(
    isFinishedJobs
      ? [
          { id: "status", desc: false },
          { id: "startTime", desc: true },
        ]
      : [{ id: "status", desc: false }],
  );
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({
    benchmark: false,
    run_name: false,
  });
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [now, setNow] = useState(Date.now());
  const [coverageByJobId, setCoverageByJobId] = useState<
    Record<
      string,
      {
        avgBlocks: number | null;
        totalBlocks: number | null;
        avgCoveragePct: number | null;
        runs: Record<string, { blocks: number | null; pct: number | null }>;
      }
    >
  >({});
  const { setTasks, setOpen } = useTasks();
  const [taskDetails, setTaskDetails] = useState<Record<string, any[]>>({});
  const [logsDialogOpen, setLogsDialogOpen] = useState(false);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [selectedRunNumber, setSelectedRunNumber] = useState<number | null>(
    null,
  );
  const [selectedLogTitle, setSelectedLogTitle] = useState<string | null>(null);
  const [selectedDownloadFilename, setSelectedDownloadFilename] = useState<
    string | null
  >(null);
  const [selectedLogUrl, setSelectedLogUrl] = useState<string | null>(null);
  const [coverageGraphOpen, setCoverageGraphOpen] = useState(false);
  const [coverageGraphJobId, setCoverageGraphJobId] = useState<string | null>(
    null,
  );
  const [coverageGraphRuns, setCoverageGraphRuns] = useState<number[]>([]);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [jobToDelete, setJobToDelete] = useState<string | null>(null);
  const [stopAllDialogOpen, setStopAllDialogOpen] = useState(false);
  const [stoppingAll, setStoppingAll] = useState(false);
  const [triagingDialogOpen, setTriagingDialogOpen] = useState(false);
  const [jobsToTriage, setJobsToTriage] = useState<Task[]>([]);
  const [loadingTriagingLogForJobId, setLoadingTriagingLogForJobId] = useState<
    string | null
  >(null);
  const [draggedQueuedJobId, setDraggedQueuedJobId] = useState<string | null>(
    null,
  );
  const [queueDropTargetJobId, setQueueDropTargetJobId] = useState<
    string | null
  >(null);
  const [cpuCount, setCpuCount] = useState<number | "">("");
  const [maxCores, setMaxCores] = useState<number>(32);
  const API_URL = useApiUrl();

  const handleShowTriagingLog = useCallback(
    async (job: Task) => {
      setLoadingTriagingLogForJobId(job.id);

      try {
        const query = new URLSearchParams({
          benchmark: job.benchmark,
          binary: job.binary,
          fuzzer: job.fuzzer,
          run_name: job.run_name,
        });

        const logUrl = `${API_URL}/api/jobs/triage-log?${query.toString()}`;
        const response = await fetch(logUrl);
        const responseData = await response.json();

        if (!response.ok) {
          toast.error(responseData.error || "No triage log found for this job");
          return;
        }

        setSelectedTaskId(null);
        setSelectedRunNumber(null);
        setSelectedLogTitle("Triaging Log");
        setSelectedDownloadFilename("triage.log");
        setSelectedLogUrl(logUrl);
        setLogsDialogOpen(true);
      } catch (error) {
        console.error("Error opening triaging log:", error);
        toast.error("Failed to open triaging log");
      } finally {
        setLoadingTriagingLogForJobId(null);
      }
    },
    [API_URL],
  );

  useEffect(() => {
    setSorting(
      isFinishedJobs
        ? [
            { id: "status", desc: false },
            { id: "startTime", desc: true },
          ]
        : [{ id: "status", desc: false }],
    );
  }, [isFinishedJobs]);

  useEffect(() => {
    const fetchCoreCount = async () => {
      try {
        const response = await fetch(`${API_URL}/api/system/cpu`);
        const data = await response.json();
        if (data.core_count) {
          setMaxCores(data.core_count);
        }
      } catch (error) {
        console.error("Failed to fetch core count:", error);
      }
    };
    fetchCoreCount();
  }, []);

  const moveJobToTop = useCallback(
    async (id: string, showToast = true) => {
      try {
        const response = await fetch(`${API_URL}/api/jobs/reorder-top`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ job_id: id }),
        });

        const responseData = await response.json();

        if (response.ok) {
          if (showToast) {
            toast.success("Job moved to top of queue");
          }
        } else {
          toast.error(responseData.error || "Failed to reorder job");
        }
      } catch (error) {
        console.error("Error moving job to top:", error);
        toast.error("Failed to reorder job");
      }
    },
    [API_URL],
  );

  const confirmDelete = async () => {
    if (!jobToDelete) return;

    try {
      const response = await fetch(`${API_URL}/api/jobs/delete`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ job_id: jobToDelete }),
      });

      const data = await response.json();

      if (response.ok) {
        toast.success(`Job ${jobToDelete} deleted`);
      } else {
        toast.error(data.error || "Failed to delete job");
      }
    } catch (error) {
      console.error("Error deleting job:", error);
      toast.error("Failed to delete job");
    } finally {
      setDeleteDialogOpen(false);
      setJobToDelete(null);
    }
  };

  const activeStoppableTasks = data.filter(
    (task) => task.status === "running" || task.status === "queued",
  );

  const confirmStopAll = async () => {
    if (activeStoppableTasks.length === 0) return;

    const jobsToStop = [...activeStoppableTasks];
    const previousStatuses = new Map(
      jobsToStop.map((task) => [task.id, task.status]),
    );
    setStoppingAll(true);

    setTasks((prevTasks) =>
      prevTasks.map((task) =>
        previousStatuses.has(task.id)
          ? { ...task, status: "stopping" }
          : task,
      ),
    );

    const outcomes = await Promise.all(
      jobsToStop.map(async (task) => {
        try {
          const response = await fetch(`${API_URL}/api/jobs/stop`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ job_id: task.id }),
          });
          return { id: task.id, ok: response.ok };
        } catch (error) {
          console.error(`Error stopping job ${task.id}:`, error);
          return { id: task.id, ok: false };
        }
      }),
    );

    const failedIds = new Set(
      outcomes.filter((outcome) => !outcome.ok).map((outcome) => outcome.id),
    );
    if (failedIds.size > 0) {
      setTasks((prevTasks) =>
        prevTasks.map((task) =>
          failedIds.has(task.id)
            ? { ...task, status: previousStatuses.get(task.id) ?? task.status }
            : task,
        ),
      );
    }

    if (failedIds.size === 0) {
      const jobLabel = jobsToStop.length === 1 ? "job" : "jobs";
      toast.success(`Stop requested for ${jobsToStop.length} active ${jobLabel}`);
    } else {
      const jobLabel = jobsToStop.length === 1 ? "job" : "jobs";
      toast.error(
        `Failed to stop ${failedIds.size} of ${jobsToStop.length} active ${jobLabel}`,
      );
    }

    setStoppingAll(false);
    setStopAllDialogOpen(false);
  };

  const confirmTriaging = async () => {
    if (jobsToTriage.length === 0) return;

    if (cpuCount === "" || cpuCount < 1) {
      toast.error("Please enter a valid CPU count");
      return;
    }

    const maxAllowed = Math.max(1, maxCores - 2);
    if (cpuCount > maxAllowed) {
      toast.error(`CPU count cannot exceed ${maxAllowed} (max cores - 2)`);
      return;
    }

    try {
      const timestamp = Date.now();
      const triagingJobs = jobsToTriage.map((job, index) => ({
        job_id: `JOB-${timestamp}-${index}-TRIAGE`,
        fuzzer: job.fuzzer,
        benchmark: job.benchmark,
        duration: job.time,
        binary: job.binary,
        runs: Number(cpuCount),
        mode: "Triaging",
        run_name: job.run_name,
      }));

      const response = await fetch(`${API_URL}/api/jobs/add`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jobs: triagingJobs,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        toast.success(
          `${triagingJobs.length} triaging job${triagingJobs.length === 1 ? "" : "s"} queued with ${cpuCount} CPU(s) each`,
        );
      } else {
        toast.error(data.error || "Failed to create triaging job");
      }
    } catch (error) {
      console.error("Error creating triaging job:", error);
      toast.error("Failed to create triaging job");
    } finally {
      setTriagingDialogOpen(false);
      setJobsToTriage([]);
      setCpuCount("");
    }
  };

  useEffect(() => {
    const handleDelete = async (id: string) => {
      setJobToDelete(id);
      setDeleteDialogOpen(true);
    };

    const handleStop = async (id: string) => {
      const currentTask = (allTasks || data).find((task) => task.id === id);
      const previousStatus = currentTask?.status;

      setTasks((prevTasks) =>
        prevTasks.map((task) =>
          task.id === id &&
          (task.status === "running" || task.status === "queued")
            ? { ...task, status: "stopping" }
            : task,
        ),
      );

      try {
        const response = await fetch(`${API_URL}/api/jobs/stop`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ job_id: id }),
        });

        const data = await response.json();

        if (response.ok) {
          toast.success(`Job ${id} is stopping`);
        } else {
          if (previousStatus) {
            setTasks((prevTasks) =>
              prevTasks.map((task) =>
                task.id === id ? { ...task, status: previousStatus } : task,
              ),
            );
          }
          toast.error(data.error || "Failed to stop job");
        }
      } catch (error) {
        if (previousStatus) {
          setTasks((prevTasks) =>
            prevTasks.map((task) =>
              task.id === id ? { ...task, status: previousStatus } : task,
            ),
          );
        }
        console.error("Error stopping job:", error);
        toast.error("Failed to stop job");
      }
    };

    const handleQueueTriaging = async (id: string) => {
      try {
        const job = data.find((task) => task.id === id);
        if (job) {
          setJobsToTriage([job]);
          setCpuCount("");
          setTriagingDialogOpen(true);
        }
      } catch (error) {
        console.error("Error opening triaging dialog:", error);
        toast.error("Failed to open triaging dialog");
      }
    };

    const handleToggleAutoTriaging = async (id: string, value: boolean) => {
      try {
        const response = await fetch(`${API_URL}/api/jobs/auto-triage`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ job_id: id, enabled: value }),
        });

        const data = await response.json();

        if (!response.ok) {
          toast.error(data.error || "Failed to update auto-triaging setting");
          return;
        }

        setTasks((prevTasks) =>
          prevTasks.map((task) =>
            task.id === id ? { ...task, autoQueueTriaging: value } : task,
          ),
        );
        toast.success(
          value ? "Auto-triaging enabled" : "Auto-triaging disabled",
        );
      } catch (error) {
        console.error("Error toggling auto-triaging:", error);
        toast.error("Failed to toggle auto-triaging");
      }
    };

    setTaskCallbacks(
      handleDelete,
      handleStop,
      handleQueueTriaging,
      handleToggleAutoTriaging,
      allTasks || data,
    );
  }, [setTasks, data, allTasks]);

  useEffect(() => {
    const interval = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const multifuzzJobIds = data
      .filter((job) => job.fuzzer === "MultiFuzz")
      .map((job) => job.id);

    if (multifuzzJobIds.length === 0) return;
    let cancelled = false;

    const fetchAll = async () => {
      const entries = await Promise.all(
        multifuzzJobIds.map(async (jobId) => {
          const empty = {
            avgBlocks: null,
            totalBlocks: null,
            avgCoveragePct: null,
            runs: {},
          } as const;
          try {
            const response = await fetch(
              `${API_URL}/api/jobs/${jobId}/coverage-summary`,
            );
            if (!response.ok) return [jobId, empty] as const;
            const data = await response.json();
            const runs: Record<
              string,
              { blocks: number | null; pct: number | null }
            > = {};
            for (const r of data.runs ?? []) {
              runs[r.run_number] = {
                blocks: r.blocks ?? null,
                pct: r.coverage_pct ?? null,
              };
            }
            return [
              jobId,
              {
                avgBlocks: data.avg_blocks ?? null,
                totalBlocks: data.total_blocks ?? null,
                avgCoveragePct: data.avg_coverage_pct ?? null,
                runs,
              },
            ] as const;
          } catch {
            return [jobId, empty] as const;
          }
        }),
      );
      if (!cancelled) {
        setCoverageByJobId(Object.fromEntries(entries));
      }
    };

    fetchAll();

    // Finished jobs' coverage is static (the run is over, stats.csv no
    // longer grows) — fetch it once instead of polling.
    if (isFinishedJobs) {
      return () => {
        cancelled = true;
      };
    }

    const interval = setInterval(fetchAll, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isFinishedJobs, data.map((j) => j.id).join(","), API_URL]);

  const fetchTaskDetails = useCallback(async (jobId: string) => {
    try {
      const response = await fetch(`${API_URL}/api/tasks/list?job_id=${jobId}`);
      const responseData = await response.json();

      console.log(`Task details response for ${jobId}:`, responseData);

      if (responseData.tasks) {
        console.log(
          `Updating taskDetails for ${jobId} with ${responseData.tasks.length} tasks`,
        );
        setTaskDetails((prev) => {
          const updated = {
            ...prev,
            [jobId]: responseData.tasks,
          };
          console.log("Updated taskDetails:", updated);
          return updated;
        });
      }
    } catch (error) {
      console.error("Failed to fetch task details:", error);
    }
  }, []);

  useEffect(() => {
    const expandedRowIds = Object.keys(expanded).filter(
      (key) => expanded[key as keyof typeof expanded],
    );

    expandedRowIds.forEach((rowId) => {
      const job = data.find((j) => j.id === rowId);
      if (job) {
        console.log(`Fetching task details for job ${rowId}`);
        fetchTaskDetails(job.id);
      }
    });
  }, [expanded, data, fetchTaskDetails]);

  useEffect(() => {
    const interval = setInterval(() => {
      const expandedRowIds = Object.keys(expanded).filter(
        (key) => expanded[key as keyof typeof expanded],
      );

      if (expandedRowIds.length > 0) {
        console.log(
          `Polling task details for ${expandedRowIds.length} expanded row(s)`,
        );
        expandedRowIds.forEach((rowId) => {
          const job = data.find((j) => j.id === rowId);
          if (job) {
            console.log(`Fetching updates for job ${rowId}`);
            fetchTaskDetails(job.id);
          }
        });
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [expanded, data, fetchTaskDetails]);

  const {
    globalFilter,
    onGlobalFilterChange,
    columnFilters,
    onColumnFiltersChange,
  } = useTableUrlState({
    search: route.useSearch(),
    navigate: route.useNavigate(),
    globalFilter: { enabled: true, key: "filter" },
  });

  const tableColumns = enableColumnSorting ? getSortableColumns() : columns;
  const benchmarkOptions = Array.from(
    new Set(data.map((task) => task.benchmark)),
  )
    .sort()
    .map((benchmark) => ({
      label: benchmark,
      value: benchmark,
    }));
  const fuzzerOptions = Array.from(new Set(data.map((task) => task.fuzzer)))
    .sort()
    .map((fuzzer) => ({
      label: fuzzer,
      value: fuzzer,
    }));
  const binaryOptions = Array.from(new Set(data.map((task) => task.binary)))
    .sort()
    .map((binary) => ({
      label: binary,
      value: binary,
    }));
  const outputDirOptions = Array.from(
    new Set(data.map((task) => task.run_name).filter(Boolean)),
  )
    .sort()
    .map((outputDir) => ({
      label: outputDir,
      value: outputDir,
    }));
  const statusOptions = isFinishedJobs
      ? [
          { label: "Triaged", value: "triaged" },
          { label: "Not triaged", value: "not-triaged" },
          { label: "Failed", value: "triage-failed" },
        { label: "Errored", value: "errored" },
        { label: "Completed", value: "completed" },
        { label: "Stopped", value: "stopped" },
      ]
    : [
        { label: "Running", value: "running" },
        { label: "Queued", value: "queued" },
        { label: "Stopping", value: "stopping" },
      ];

  const table = useReactTable({
    data,
    columns: tableColumns,
    getRowId: (row) => row.id,
    state: {
      sorting,
      columnVisibility,
      columnFilters,
      globalFilter,
      expanded,
    },
    meta: {
      now,
      coverageByJobId,
    },
    onSortingChange: setSorting,
    onColumnVisibilityChange: setColumnVisibility,
    onExpandedChange: setExpanded,
    getExpandedRowModel: getExpandedRowModel(),
    globalFilterFn: (row, _columnId, filterValue) => {
      const benchmark = String(row.getValue("benchmark")).toLowerCase();
      const status = String(row.getValue("status")).toLowerCase();
      const mode = String(row.getValue("mode")).toLowerCase();
      const fuzzer = String(row.getValue("fuzzer")).toLowerCase();
      const binary = String(row.getValue("binary")).toLowerCase();
      const searchValue = String(filterValue).toLowerCase();

      return (
        benchmark.includes(searchValue) ||
        status.includes(searchValue) ||
        mode.includes(searchValue) ||
        fuzzer.includes(searchValue) ||
        binary.includes(searchValue)
      );
    },
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    onGlobalFilterChange,
    onColumnFiltersChange,
  });

  const getVisibleTriageCandidates = () => {
    const knownTasks = allTasks || data;
    return table
      .getFilteredRowModel()
      .rows.map((row) => row.original)
      .filter((job) => {
        if (job.mode === "Triaging") return false;

        const relatedTriagingJobs = knownTasks.filter(
          (task) =>
            task.mode === "Triaging" &&
            task.benchmark === job.benchmark &&
            task.binary === job.binary &&
            task.fuzzer === job.fuzzer &&
            task.run_name === job.run_name,
        );

        // Do not create duplicate work while an earlier triage request is
        // queued or running. Errored/stopped triage jobs remain retryable.
        return !relatedTriagingJobs.some(
          (task) => task.status === "queued" || task.status === "running",
        );
      });
  };

  const visibleTriageCount = isFinishedJobs
    ? getVisibleTriageCandidates().length
    : 0;

  const handleQueueVisibleTriaging = () => {
    const candidates = getVisibleTriageCandidates();
    if (candidates.length === 0) {
      toast.info("There are no eligible fuzzing jobs in the current view");
      return;
    }

    setJobsToTriage(candidates);
    setCpuCount("");
    setTriagingDialogOpen(true);
  };

  return (
    <div
      className={cn(
        'max-sm:has-[div[role="toolbar"]]:mb-16',
        "flex flex-1 flex-col gap-4",
      )}
    >
      <DataTableToolbar
        table={table}
        searchPlaceholder="Filter"
        filters={
          [
            {
              columnId: "status",
              title: "Status",
              options: statusOptions,
            },
            benchmarkOptions.length > 0
              ? {
                  columnId: "benchmark",
                  title: "Benchmark",
                  options: benchmarkOptions,
                }
              : null,
            fuzzerOptions.length > 0
              ? {
                  columnId: "fuzzer",
                  title: "Fuzzer",
                  options: fuzzerOptions,
                }
              : null,
            binaryOptions.length > 0
              ? {
                  columnId: "binary",
                  title: "Binary",
                  options: binaryOptions,
                }
              : null,
            outputDirOptions.length > 0
              ? {
                  columnId: "run_name",
                  title: "Output Dir",
                  options: outputDirOptions,
                }
              : null,
          ].filter(Boolean) as {
            columnId: string;
            title: string;
            options: { label: string; value: string }[];
          }[]
        }
        createButton={
          showCreateButton || isFinishedJobs ? (
            <div className="ms-auto hidden shrink-0 items-center justify-end gap-3 lg:flex">
              {!isFinishedJobs ? (
                <Button
                  variant="destructive"
                  size="sm"
                  className="h-8 shrink-0 whitespace-nowrap"
                  onClick={() => setStopAllDialogOpen(true)}
                  disabled={activeStoppableTasks.length === 0 || stoppingAll}
                  title="Stop all queued and running jobs"
                >
                  <CircleStop className="size-4" />
                  Stop all
                </Button>
              ) : null}
              {isFinishedJobs ? (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 shrink-0 whitespace-nowrap"
                  onClick={handleQueueVisibleTriaging}
                  disabled={visibleTriageCount === 0}
                  title="Queue triaging for every eligible fuzzing job currently visible"
                >
                  <ListChecks className="size-4" />
                  Triage all ({visibleTriageCount})
                </Button>
              ) : null}
              {showCreateButton ? (
                <Button
                  size="sm"
                  className="h-8 shrink-0 whitespace-nowrap"
                  onClick={() => setOpen("create")}
                >
                  <Plus className="size-4" />
                  Add
                </Button>
              ) : null}
            </div>
          ) : undefined
        }
      />
      <div className="relative">
        <div className="overflow-x-auto overflow-y-visible rounded-md border scroll-smooth">
          {toolbarExtras ? (
            <div className="flex items-center justify-end border-b bg-muted/20 px-3 py-2">
              {toolbarExtras}
            </div>
          ) : null}
          <Table className="min-w-xl">
            <TableHeader>
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id}>
                  {headerGroup.headers.map((header) => {
                    return (
                      <TableHead
                        key={header.id}
                        colSpan={header.colSpan}
                        className={cn(
                          header.column.columnDef.meta?.className,
                          header.column.columnDef.meta?.thClassName,
                        )}
                      >
                        {header.isPlaceholder
                          ? null
                          : flexRender(
                              header.column.columnDef.header,
                              header.getContext(),
                            )}
                      </TableHead>
                    );
                  })}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {table.getRowModel().rows?.length ? (
                table.getRowModel().rows.map((row) => {
                  const isQueuedRow = row.original.status === "queued";
                  const canDragQueued = !isFinishedJobs && isQueuedRow;
                  const isQueueDropTarget =
                    queueDropTargetJobId === row.original.id;
                  const relatedTriagingJobs = (allTasks || data).filter(
                    (task) =>
                      task.mode === "Triaging" &&
                      task.benchmark === row.original.benchmark &&
                      task.binary === row.original.binary &&
                      task.fuzzer === row.original.fuzzer &&
                      task.run_name === row.original.run_name,
                  );
                  const hasTriagingError = relatedTriagingJobs.some(
                    (task) => task.status === "errored",
                  );
                  return (
                    <Fragment key={row.id}>
                      <TableRow
                        data-state={row.getIsSelected() && "selected"}
                        className={cn(
                          "cursor-pointer",
                          canDragQueued && "cursor-grab active:cursor-grabbing",
                          isQueueDropTarget &&
                            "ring-1 ring-primary/50 bg-primary/5",
                        )}
                        draggable={canDragQueued}
                        onDragStart={(e) => {
                          if (!canDragQueued) return;
                          setDraggedQueuedJobId(row.original.id);
                          e.dataTransfer.effectAllowed = "move";
                          e.dataTransfer.setData("text/plain", row.original.id);
                        }}
                        onDragEnd={() => {
                          setDraggedQueuedJobId(null);
                          setQueueDropTargetJobId(null);
                        }}
                        onDragOver={(e) => {
                          if (!canDragQueued || !draggedQueuedJobId) return;
                          e.preventDefault();
                          e.dataTransfer.dropEffect = "move";
                          setQueueDropTargetJobId(row.original.id);
                        }}
                        onDragLeave={() => {
                          if (queueDropTargetJobId === row.original.id) {
                            setQueueDropTargetJobId(null);
                          }
                        }}
                        onDrop={(e) => {
                          if (!canDragQueued || !draggedQueuedJobId) return;
                          e.preventDefault();
                          e.stopPropagation();
                          const droppedJobId =
                            e.dataTransfer.getData("text/plain") ||
                            draggedQueuedJobId;
                          if (
                            droppedJobId &&
                            droppedJobId !== row.original.id
                          ) {
                            moveJobToTop(droppedJobId);
                          }
                          setDraggedQueuedJobId(null);
                          setQueueDropTargetJobId(null);
                        }}
                      >
                        {row.getVisibleCells().map((cell) => (
                          <TableCell
                            key={cell.id}
                            className={cn(
                              cell.column.columnDef.meta?.className,
                              cell.column.columnDef.meta?.tdClassName,
                            )}
                            onClick={(e) => {
                              if (cell.column.id === "actions") {
                                e.stopPropagation();
                                return;
                              }
                              row.toggleExpanded();
                              if (!row.getIsExpanded()) {
                                fetchTaskDetails(row.original.id);
                              }
                            }}
                          >
                            {flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext(),
                            )}
                          </TableCell>
                        ))}
                      </TableRow>
                      {row.getIsExpanded() && (
                        <TableRow key={`${row.id}-expanded`}>
                          <TableCell
                            colSpan={columns.length}
                            className="bg-gradient-to-br from-muted/30 via-muted/20 to-transparent p-0"
                          >
                            <div className="p-6 space-y-4 animate-in slide-in-from-top-2 duration-300">
                              {/* Header Section */}
                              <div className="flex items-start justify-between">
                                <div className="space-y-1">
                                  <h3 className="text-lg font-semibold flex items-center gap-2">
                                    <Activity className="h-5 w-5 text-primary" />
                                    Individual Task Runs
                                  </h3>
                                  <p className="text-sm text-muted-foreground">
                                    Job ID:{" "}
                                    <span className="font-mono">
                                      {row.original.id}
                                    </span>
                                  </p>
                                </div>
                                {row.original.fuzzer === "MultiFuzz" &&
                                  row.original.mode !== "Triaging" && (
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      className="h-8 text-xs"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        const runs: number[] = (
                                          taskDetails[row.original.id] || []
                                        )
                                          .map(
                                            (task: { run_number: number }) =>
                                              task.run_number,
                                          )
                                          .sort((a: number, b: number) => a - b);
                                        setCoverageGraphJobId(row.original.id);
                                        setCoverageGraphRuns(runs);
                                        setCoverageGraphOpen(true);
                                      }}
                                    >
                                      <Activity className="h-3.5 w-3.5 mr-1.5" />
                                      Coverage Graph
                                    </Button>
                                  )}
                              </div>

                              {/* Run Path Section */}
                              {row.original.run_path && (
                                <>
                                  <div className="space-y-2">
                                    <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wide flex items-center gap-2">
                                      <FolderOutput className="h-4 w-4" />
                                      Run Path
                                    </h4>
                                    <div className="bg-muted/50 rounded-md p-3 border border-border">
                                      <code className="text-xs font-mono text-foreground break-all">
                                        {row.original.run_path}
                                      </code>
                                    </div>
                                  </div>
                                </>
                              )}

                              <Separator />

                              {/* Individual Task Details Table */}
                              {taskDetails[row.original.id] &&
                              taskDetails[row.original.id].length > 0 ? (
                                <div className="rounded-md border">
                                  <div className="overflow-x-auto">
                                    <Table>
                                      <TableHeader className="sticky top-0 bg-background z-10">
                                        <TableRow>
                                          <TableHead className="w-[70px]">
                                            Run #
                                          </TableHead>
                                          <TableHead className="w-[90px]">
                                            Status
                                          </TableHead>
                                          <TableHead className="w-[60px]">
                                            CPU
                                          </TableHead>
                                          {row.original.mode !== "Triaging" && (
                                            <TableHead className="w-[180px]">
                                              CPU Usage
                                            </TableHead>
                                          )}
                                          {row.original.fuzzer ===
                                            "MultiFuzz" &&
                                            row.original.mode !==
                                              "Triaging" && (
                                              <TableHead className="w-[110px]">
                                                Coverage
                                              </TableHead>
                                            )}
                                          <TableHead className="w-[180px]">
                                            Container
                                          </TableHead>
                                          <TableHead className="w-[180px]">
                                            Started At
                                          </TableHead>
                                          <TableHead className="w-[180px]">
                                            Completed At
                                          </TableHead>
                                          <TableHead className="w-[120px]">
                                            Actions
                                          </TableHead>
                                        </TableRow>
                                      </TableHeader>
                                      <TableBody>
                                        {taskDetails[row.original.id].map(
                                          (task: any) => (
                                            <TableRow
                                              key={task.task_id}
                                              className="hover:bg-muted/50"
                                            >
                                              <TableCell className="font-mono font-semibold text-primary">
                                                #{task.run_number}
                                              </TableCell>
                                              <TableCell>
                                                <Badge
                                                  variant={
                                                    task.status === "running"
                                                      ? "default"
                                                      : task.status ===
                                                          "completed"
                                                        ? "outline"
                                                        : task.status ===
                                                            "errored"
                                                          ? "destructive"
                                                          : "secondary"
                                                  }
                                                  className={cn(
                                                    "text-xs",
                                                    task.status === "running" &&
                                                      "bg-blue-500 hover:bg-blue-600 text-white",
                                                    task.status ===
                                                      "completed" &&
                                                      "bg-green-500/10 text-green-700 dark:text-green-400 border-green-500/20",
                                                  )}
                                                >
                                                  {task.status}
                                                </Badge>
                                              </TableCell>
                                              <TableCell className="font-mono text-sm">
                                                {(() => {
                                                  if (
                                                    task.core_idx === null ||
                                                    task.core_idx === undefined
                                                  ) {
                                                    return "-";
                                                  }

                                                  if (!Array.isArray(task.core_idx)) {
                                                    return task.core_idx;
                                                  }

                                                  const allCores = task.core_idx.join(", ");
                                                  const previewCores =
                                                    task.core_idx.length > 4
                                                      ? `${task.core_idx
                                                          .slice(0, 4)
                                                          .join(", ")}, ...`
                                                      : allCores;

                                                  return (
                                                    <span
                                                      className="inline-block max-w-[120px] truncate align-bottom"
                                                      title={allCores}
                                                    >
                                                      {previewCores}
                                                    </span>
                                                  );
                                                })()}
                                              </TableCell>
                                              {row.original.mode !==
                                                "Triaging" && (
                                                <TableCell>
                                                  {task.cpu_usage !== null &&
                                                  task.cpu_usage !==
                                                    undefined ? (
                                                    Array.isArray(
                                                      task.cpu_usage,
                                                    ) ? (
                                                      (() => {
                                                        const avg =
                                                          task.cpu_usage.reduce(
                                                            (
                                                              a: number,
                                                              b: number,
                                                            ) => a + b,
                                                            0,
                                                          ) /
                                                          task.cpu_usage.length;
                                                        return (
                                                          <div className="flex items-center gap-2">
                                                            <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                                                              <div
                                                                className={cn(
                                                                  "h-full transition-all duration-300",
                                                                  avg > 80
                                                                    ? "bg-red-500"
                                                                    : avg > 50
                                                                      ? "bg-yellow-500"
                                                                      : "bg-green-500",
                                                                )}
                                                                style={{
                                                                  width: `${avg}%`,
                                                                }}
                                                              />
                                                            </div>
                                                            <span className="font-mono text-xs text-muted-foreground whitespace-nowrap min-w-[45px]">
                                                              {avg.toFixed(1)}%
                                                            </span>
                                                          </div>
                                                        );
                                                      })()
                                                    ) : (
                                                      <div className="flex items-center gap-2">
                                                        <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                                                          <div
                                                            className={cn(
                                                              "h-full transition-all duration-300",
                                                              task.cpu_usage >
                                                                80
                                                                ? "bg-red-500"
                                                                : task.cpu_usage >
                                                                    50
                                                                  ? "bg-yellow-500"
                                                                  : "bg-green-500",
                                                            )}
                                                            style={{
                                                              width: `${task.cpu_usage}%`,
                                                            }}
                                                          />
                                                        </div>
                                                        <span className="font-mono text-xs text-muted-foreground whitespace-nowrap min-w-[45px]">
                                                          {task.cpu_usage.toFixed(
                                                            1,
                                                          )}
                                                          %
                                                        </span>
                                                      </div>
                                                    )
                                                  ) : (
                                                    <span className="text-muted-foreground text-xs">
                                                      -
                                                    </span>
                                                  )}
                                                </TableCell>
                                              )}
                                              {row.original.fuzzer ===
                                                "MultiFuzz" &&
                                                row.original.mode !==
                                                  "Triaging" && (
                                                  <TableCell className="font-mono text-xs">
                                                    {(() => {
                                                      const run =
                                                        coverageByJobId[
                                                          row.original.id
                                                        ]?.runs[
                                                          task.run_number
                                                        ];
                                                      if (run?.blocks == null) {
                                                        return (
                                                          <span className="text-muted-foreground">
                                                            —
                                                          </span>
                                                        );
                                                      }
                                                      return (
                                                        <span className="inline-flex items-center gap-1.5">
                                                          <Activity className="h-3 w-3 text-primary" />
                                                          {run.blocks.toLocaleString()}
                                                          {run.pct != null && (
                                                            <span className="text-muted-foreground">
                                                              ({run.pct}%)
                                                            </span>
                                                          )}
                                                        </span>
                                                      );
                                                    })()}
                                                  </TableCell>
                                                )}
                                              <TableCell
                                                className="font-mono text-xs truncate max-w-[150px]"
                                                title={task.container_name}
                                              >
                                                {task.container_name || "-"}
                                              </TableCell>
                                              <TableCell className="text-xs text-muted-foreground">
                                                {task.started_at
                                                  ? new Date(
                                                      task.started_at * 1000,
                                                    ).toLocaleString()
                                                  : "-"}
                                              </TableCell>
                                              <TableCell className="text-xs text-muted-foreground">
                                                {task.completed_at
                                                  ? new Date(
                                                      task.completed_at * 1000,
                                                    ).toLocaleString()
                                                  : "-"}
                                              </TableCell>
                                              <TableCell>
                                                <Button
                                                  variant="outline"
                                                  size="sm"
                                                  className="h-8 text-xs"
                                                  onClick={(e) => {
                                                    e.stopPropagation();
                                                    setSelectedTaskId(
                                                      task.task_id,
                                                    );
                                                    setSelectedRunNumber(
                                                      task.run_number,
                                                    );
                                                    setSelectedLogTitle(null);
                                                    setSelectedDownloadFilename(
                                                      null,
                                                    );
                                                    setSelectedLogUrl(null);
                                                    setLogsDialogOpen(true);
                                                  }}
                                                >
                                                  <FolderOutput className="h-3.5 w-3.5 mr-1.5" />
                                                  Show Logs
                                                </Button>
                                              </TableCell>
                                            </TableRow>
                                          ),
                                        )}
                                      </TableBody>
                                    </Table>
                                  </div>
                                </div>
                              ) : !taskDetails[row.original.id] ? (
                                <div className="flex items-center justify-center py-12 text-muted-foreground border rounded-md bg-muted/20">
                                  <div className="flex items-center gap-2">
                                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary"></div>
                                    <span className="text-sm">
                                      Loading task details...
                                    </span>
                                  </div>
                                </div>
                              ) : (
                                <div className="flex items-center justify-center py-12 text-muted-foreground border rounded-md bg-muted/20">
                                  <div className="text-center space-y-2">
                                    <Hash className="h-8 w-8 mx-auto opacity-50" />
                                    <p className="text-sm">
                                      No tasks found for this job
                                    </p>
                                  </div>
                                </div>
                              )}

                              {isFinishedJobs &&
                                row.original.mode !== "Triaging" &&
                                ((row.original.triaged ?? false) ||
                                  hasTriagingError) && (
                                  <div className="pt-1">
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      className="h-8 text-xs"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleShowTriagingLog(row.original);
                                      }}
                                      disabled={
                                        loadingTriagingLogForJobId ===
                                        row.original.id
                                      }
                                    >
                                      <FolderOutput className="h-3.5 w-3.5 mr-1.5" />
                                      {loadingTriagingLogForJobId ===
                                      row.original.id
                                        ? "Loading triage log..."
                                        : "Show triage log"}
                                    </Button>
                                  </div>
                                )}
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell
                    colSpan={columns.length}
                    className="h-24 text-center"
                  >
                    {isFinishedJobs
                      ? "No finished jobs match these filters."
                      : "No active jobs match these filters."}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Task Logs Dialog */}
      <TaskLogsDialog
        open={logsDialogOpen}
        onOpenChange={setLogsDialogOpen}
        taskId={selectedTaskId}
        runNumber={selectedRunNumber}
        title={selectedLogTitle}
        downloadFilename={selectedDownloadFilename}
        logUrl={selectedLogUrl}
      />

      {/* Coverage Graph Dialog */}
      <CoverageGraphDialog
        open={coverageGraphOpen}
        onOpenChange={setCoverageGraphOpen}
        jobId={coverageGraphJobId}
        runNumbers={coverageGraphRuns}
      />

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title="Delete Job"
        desc="The output directory will be deleted as well. Are you sure you want to delete this job?"
        destructive
        confirmText="Yes, Delete"
        cancelBtnText="No, Cancel"
        handleConfirm={confirmDelete}
      />

      {/* Stop All Confirmation Dialog */}
      <ConfirmDialog
        open={stopAllDialogOpen}
        onOpenChange={setStopAllDialogOpen}
        title="Stop All Active Jobs"
        desc={`This will stop ${activeStoppableTasks.length} queued or running ${activeStoppableTasks.length === 1 ? "job" : "jobs"}. Are you sure?`}
        destructive
        confirmText="Yes, Stop All"
        cancelBtnText="No, Cancel"
        handleConfirm={confirmStopAll}
        isLoading={stoppingAll}
      />

      {/* Triaging Dialog */}
      <Dialog open={triagingDialogOpen} onOpenChange={setTriagingDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Queue Triaging Job</DialogTitle>
            <DialogDescription>
              Queue triaging for {jobsToTriage.length} visible fuzzing job
              {jobsToTriage.length === 1 ? "" : "s"}. How many CPUs should each
              triaging job use?
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="cpu-count" className="text-right">
                CPU Count
              </Label>
              <div className="col-span-3 space-y-1">
                <Input
                  id="cpu-count"
                  type="number"
                  min="1"
                  max={Math.max(1, maxCores - 2)}
                  value={cpuCount}
                  onChange={(e) => {
                    const value = e.target.value;
                    if (value === "") {
                      setCpuCount("");
                    } else {
                      const numValue = parseInt(value);
                      const maxAllowed = Math.max(1, maxCores - 2);
                      if (!isNaN(numValue)) {
                        setCpuCount(
                          Math.min(Math.max(1, numValue), maxAllowed),
                        );
                      }
                    }
                  }}
                  placeholder="Enter CPU count"
                />
                <p className="text-xs text-muted-foreground">
                  Max allowed: {Math.max(1, maxCores - 2)} (total cores - 2)
                </p>
              </div>
            </div>
            {jobsToTriage.length > 0 && (
              <div className="text-sm text-muted-foreground space-y-1 border-t pt-4">
                <p><strong>Jobs:</strong> {jobsToTriage.length}</p>
                <p>
                  <strong>Scope:</strong>{" "}
                  {jobsToTriage.length === 1
                    ? `${jobsToTriage[0].fuzzer} / ${jobsToTriage[0].benchmark} / ${jobsToTriage[0].binary}`
                    : "all eligible jobs matching the current filters"}
                </p>
                <p>
                  <strong>Mode:</strong> Triaging
                </p>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setTriagingDialogOpen(false);
                setJobsToTriage([]);
              }}
            >
              Cancel
            </Button>
            <Button onClick={confirmTriaging}>Create Triaging Job</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
