import { type ColumnDef } from "@tanstack/react-table";
import {
  Trash2,
  CircleStop,
  Search,
  MoreHorizontal,
  CheckCircle2,
  FileCheck,
  CircleAlert,
  LoaderCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import { DataTableColumnHeader } from "@/components/data-table";
import { type Task } from "../data/schema";
import { formatTime } from "./tasks-mutate-drawer";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

function formatDateTime(value: Date | string | undefined): string {
  if (!value) return "-";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

let deleteTaskCallback: ((id: string) => void) | null = null;
let stopTaskCallback: ((id: string) => void) | null = null;
let queueTriagingCallback: ((id: string) => void) | null = null;
let toggleAutoTriagingCallback: ((id: string, value: boolean) => void) | null =
  null;
let allTasks: Task[] = [];

function getRelatedTriagingJobs(task: Task): Task[] {
  return allTasks.filter(
    (candidate) =>
      candidate.mode === "Triaging" &&
      candidate.benchmark === task.benchmark &&
      candidate.binary === task.binary &&
      candidate.fuzzer === task.fuzzer &&
      candidate.run_name === task.run_name,
  );
}

function hasFinishedTriagingError(task: Task): boolean {
  const relatedTriagingJobs = getRelatedTriagingJobs(task);
  return (
    relatedTriagingJobs.some((candidate) => candidate.status === "errored") &&
    !relatedTriagingJobs.some(
      (candidate) =>
        candidate.status === "running" || candidate.status === "queued",
    ) &&
    !relatedTriagingJobs.some((candidate) => candidate.status === "completed")
  );
}

export function setTaskCallbacks(
  deleteFn: (id: string) => void,
  stopFn: (id: string) => void,
  queueTriagingFn: (id: string) => void,
  toggleAutoTriagingFn: (id: string, value: boolean) => void,
  tasks: Task[],
) {
  deleteTaskCallback = deleteFn;
  stopTaskCallback = stopFn;
  queueTriagingCallback = queueTriagingFn;
  toggleAutoTriagingCallback = toggleAutoTriagingFn;
  allTasks = tasks;
}

export const tasksColumns: ColumnDef<Task>[] = [
  {
    accessorKey: "status",
    header: () => <div className="pl-4">Status</div>,
    enableSorting: true,
    filterFn: (row, id, value) => {
      const selected = Array.isArray(value) ? value : [value];
      const status = String(row.getValue(id));

      return selected.some(
        (filterValue) =>
          filterValue === status ||
          (filterValue === "triaged" && row.original.triaged === true) ||
          (filterValue === "not-triaged" && row.original.triaged !== true) ||
          (filterValue === "triage-failed" &&
            hasFinishedTriagingError(row.original)),
      );
    },
    sortingFn: (rowA, rowB) => {
      const statusOrder = {
        running: 0,
        queued: 1,
        stopping: 2,
        errored: 3,
        stopped: 4,
        completed: 5,
      };
      const statusA = rowA.original.status;
      const statusB = rowB.original.status;
      const orderA = statusOrder[statusA as keyof typeof statusOrder] ?? 999;
      const orderB = statusOrder[statusB as keyof typeof statusOrder] ?? 999;

      if (orderA !== orderB) {
        return orderA - orderB;
      }

      const activeStatuses = new Set(["running", "queued", "stopping"]);
      if (!activeStatuses.has(statusA) || !activeStatuses.has(statusB)) {
        return 0;
      }

      const posA = rowA.original.queuePosition ?? 999999;
      const posB = rowB.original.queuePosition ?? 999999;
      return posA - posB;
    },
    cell: ({ row }) => {
      const status = row.getValue("status") as string;
      const statusConfig = {
        running: {
          label: "Running",
          className: "bg-blue-500 hover:bg-blue-600 text-white",
        },
        queued: {
          label: "Queued",
          className: "bg-gray-500 hover:bg-gray-600 text-white",
        },
        stopping: {
          label: "Stopping",
          className: "bg-yellow-400 hover:bg-yellow-500 text-white",
        },
        completed: {
          label: "Completed",
          className: "bg-green-500 hover:bg-green-600 text-white",
        },
        stopped: {
          label: "Stopped",
          className: "bg-yellow-500 hover:bg-yellow-600 text-white",
        },
        errored: {
          label: "Errored",
          className: "bg-red-500 hover:bg-red-600 text-white",
        },
      };
      const config = statusConfig[status as keyof typeof statusConfig] || {
        label: status,
        className: "bg-gray-500 text-white",
      };
      return (
        <div className="w-[100px] pl-4">
          <Badge className={config.className}>{config.label}</Badge>
        </div>
      );
    },
  },
  {
    accessorKey: "benchmark",
    header: () => <div className="pl-4">Benchmark</div>,
    enableSorting: false,
    filterFn: (row, id, value) => {
      if (!Array.isArray(value) || value.length === 0) return true;
      return value.includes(row.getValue(id));
    },
    cell: ({ row }) => (
      <div className="w-[120px] pl-4">{String(row.getValue("benchmark"))}</div>
    ),
  },
  {
    accessorKey: "mode",
    header: () => <div className="pl-4">Mode</div>,
    enableSorting: false,
    cell: ({ row }) => {
      const mode = row.getValue("mode") as string;
      return <div className="w-[100px] pl-4">{mode}</div>;
    },
  },
  {
    accessorKey: "fuzzer",
    header: () => <div className="pl-4">Fuzzer</div>,
    enableSorting: false,
    cell: ({ row, table }) => {
      const fuzzer = String(row.getValue("fuzzer"));
      const coverage =
        fuzzer === "MultiFuzz"
          ? (
              table.options.meta as
                | {
                    coverageByJobId?: Record<
                      string,
                      {
                        avgBlocks: number | null;
                        totalBlocks: number | null;
                        avgCoveragePct: number | null;
                      }
                    >;
                  }
                | undefined
            )?.coverageByJobId?.[row.original.id]
          : undefined;
      const avgBlocks = coverage?.avgBlocks;
      const totalBlocks = coverage?.totalBlocks;
      const avgCoveragePct = coverage?.avgCoveragePct;
      return (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="w-[120px] pl-4 truncate">
                {fuzzer}
                {avgBlocks != null && (
                  <div className="text-xs text-muted-foreground font-mono">
                    ~{Math.round(avgBlocks).toLocaleString()}
                    {totalBlocks != null
                      ? `/${totalBlocks.toLocaleString()} blocks`
                      : " blocks"}
                    {avgCoveragePct != null && ` (${avgCoveragePct}%)`}
                  </div>
                )}
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p>{fuzzer}</p>
              {avgBlocks != null && (
                <p className="text-xs text-muted-foreground">
                  Avg coverage: {Math.round(avgBlocks).toLocaleString()}
                  {totalBlocks != null
                    ? ` / ${totalBlocks.toLocaleString()} valid blocks`
                    : " blocks"}
                  {avgCoveragePct != null && ` (${avgCoveragePct}%)`}
                </p>
              )}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      );
    },
  },
  {
    accessorKey: "binary",
    header: () => <div className="pl-4">Binary</div>,
    enableSorting: false,
    cell: ({ row }) => {
      const binary = row.getValue("binary") as string;
      const benchmark = row.original.benchmark;
      return (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="w-[120px] pl-4">
                <div className="text-xs text-muted-foreground">{benchmark}</div>
                <div className="truncate">{binary}</div>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p className="text-xs text-muted-foreground">{benchmark}</p>
              <p>{binary}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      );
    },
  },
  {
    accessorKey: "run_name",
    header: () => <div className="pl-4">Run Name</div>,
    enableSorting: false,
    filterFn: (row, id, value) => {
      if (!Array.isArray(value) || value.length === 0) return true;
      return value.includes(row.getValue(id));
    },
    cell: ({ row }) => (
      <div
        className="w-[160px] pl-4 truncate"
        title={String(row.getValue("run_name") || "")}
      >
        {String(row.getValue("run_name") || "-")}
      </div>
    ),
  },
  {
    accessorKey: "runs",
    header: () => <div className="pl-4">Runs</div>,
    enableSorting: false,
    cell: ({ row }) => (
      <div className="w-[100px] font-mono pl-4">{row.getValue("runs")}</div>
    ),
  },
  {
    accessorKey: "startTime",
    header: () => <div className="pl-4">Started</div>,
    sortingFn: (rowA, rowB) => {
      const getSortTime = (task: Task) => {
        const source = task.startTime ?? task.createdAt;
        const date = source instanceof Date ? source : new Date(source);
        return Number.isNaN(date.getTime()) ? 0 : date.getTime();
      };

      return getSortTime(rowA.original) - getSortTime(rowB.original);
    },
    cell: ({ row }) => {
      const startTime = row.original.startTime;

      return (
        <div className="w-[170px] pl-4 pr-3">
          <div className="text-sm whitespace-nowrap">
            {formatDateTime(startTime)}
          </div>
        </div>
      );
    },
  },
  {
    accessorKey: "completedAt",
    id: "time",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Time" />
    ),
    sortingFn: (rowA, rowB) => {
      const completedA = rowA.original.completedAt;
      const completedB = rowB.original.completedAt;

      if (completedA && completedB) {
        const timeA =
          completedA instanceof Date
            ? completedA.getTime()
            : new Date(completedA).getTime();
        const timeB =
          completedB instanceof Date
            ? completedB.getTime()
            : new Date(completedB).getTime();
        return timeA - timeB;
      }

      if (completedA && !completedB) return -1;
      if (!completedA && completedB) return 1;

      return rowA.original.progress - rowB.original.progress;
    },
    cell: ({ row }) => {
      const progress = row.original.progress ?? 0;
      const totalTime = row.original.time;
      const status = row.original.status;
      const mode = row.original.mode;
      const elapsedTime = row.original.elapsedTime ?? 0;
      const isRunningTriaging = status === "running" && mode === "Triaging";
      const isRunningFuzzing = status === "running" && mode !== "Triaging";

      let timeRemaining = Math.max(0, totalTime - elapsedTime);
      if (progress >= 100) {
        timeRemaining = 0;
      }

      const barColorClass =
        status === "completed"
          ? "bg-green-500"
          : status === "errored"
            ? "bg-red-500"
            : status === "stopped"
              ? "bg-yellow-500"
              : status === "stopping"
                ? "bg-yellow-400"
                : "bg-primary";

      return (
        <div className="flex flex-col items-center gap-2 w-full min-w-[250px] pl-3">
          <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${barColorClass} ${isRunningFuzzing || isRunningTriaging ? "animate-pulse" : ""}`}
              style={{ width: `${isRunningTriaging ? 100 : progress}%` }}
            />
          </div>
          {status === "running" && mode === "Triaging" && (
            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
              in progress
            </span>
          )}
          {status === "running" && mode !== "Triaging" && (
            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
              {formatTime(timeRemaining)} remaining
            </span>
          )}
          {status === "stopping" && (
            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
              stopping...
            </span>
          )}
          {status === "queued" && mode === "Triaging" && (
            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
              queued
            </span>
          )}
          {status === "queued" && mode !== "Triaging" && (
            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
              {formatTime(totalTime)} queued
            </span>
          )}
          {(status === "completed" || status === "stopped") && (
            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
              {formatTime(totalTime)} {status}
            </span>
          )}
          {status === "errored" && (
            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
              {formatTime(elapsedTime)} errored
            </span>
          )}
        </div>
      );
    },
  },
  {
    id: "actions",
    header: () => <div className="w-[60px]"></div>,
    cell: ({ row }) => {
      const status = row.original.status;
      const isActive = status === "running" || status === "queued";
      const isFinished =
        status === "completed" || status === "stopped" || status === "errored";
      const mode = row.original.mode;
      const isTriagingMode = mode === "Triaging";
      const autoQueueTriaging = isTriagingMode
        ? false
        : (row.original.autoQueueTriaging ?? true);
      const triaged = row.original.triaged ?? false;
      const relatedTriagingJobs = getRelatedTriagingJobs(row.original);
      const hasActiveTriaging = relatedTriagingJobs.some(
        (task) => task.status === "running" || task.status === "queued",
      );
      const showTriagingFailed =
        hasFinishedTriagingError(row.original) && !isTriagingMode;

      return (
        <div
          className="flex items-center justify-center gap-2"
          onClick={(e) => e.stopPropagation()}
        >
          {isActive && autoQueueTriaging && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                </TooltipTrigger>
                <TooltipContent>
                  <p>Auto-triaging enabled</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {isFinished && showTriagingFailed && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <CircleAlert className="h-4 w-4 text-red-500" />
                </TooltipTrigger>
                <TooltipContent>
                  <p>Triaging failed</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {isFinished &&
            triaged &&
            !showTriagingFailed &&
            !hasActiveTriaging && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <FileCheck className="h-4 w-4 text-blue-500" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Triaged</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
          {isFinished && hasActiveTriaging && !isTriagingMode && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <LoaderCircle className="h-4 w-4 text-amber-500 animate-spin" />
                </TooltipTrigger>
                <TooltipContent>
                  <p>Triaging</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          <DropdownMenu modal={false}>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={(e) => {
                  e.stopPropagation();
                }}
              >
                <MoreHorizontal className="h-4 w-4" />
                <span className="sr-only">Open menu</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="w-56"
              onClick={(e) => e.stopPropagation()}
            >
              {isActive && (
                <>
                  <DropdownMenuLabel>Actions</DropdownMenuLabel>
                  <DropdownMenuItem
                    onClick={(e) => {
                      e.stopPropagation();
                      stopTaskCallback?.(row.original.id);
                    }}
                  >
                    <CircleStop className="mr-2 h-4 w-4" />
                    Stop
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuLabel>Settings</DropdownMenuLabel>
                  <div className="px-2 py-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Search className="h-4 w-4" />
                        <span className="text-sm">Auto-queue triaging</span>
                      </div>
                      <Switch
                        checked={autoQueueTriaging}
                        onCheckedChange={(checked) => {
                          toggleAutoTriagingCallback?.(
                            row.original.id,
                            checked,
                          );
                        }}
                        onClick={(e) => e.stopPropagation()}
                        disabled={isTriagingMode}
                      />
                    </div>
                  </div>
                </>
              )}
              {isFinished && (
                <>
                  {(() => {
                    const hasRunningTriaging = allTasks.some(
                      (task) =>
                        task.benchmark === row.original.benchmark &&
                        task.binary === row.original.binary &&
                        task.fuzzer === row.original.fuzzer &&
                        task.mode === "Triaging" &&
                        (task.status === "running" || task.status === "queued"),
                    );
                    return (
                      <DropdownMenuItem
                        onClick={(e) => {
                          e.stopPropagation();
                          if (!hasRunningTriaging) {
                            queueTriagingCallback?.(row.original.id);
                          }
                        }}
                        disabled={hasRunningTriaging}
                        className={
                          hasRunningTriaging
                            ? "opacity-50 cursor-not-allowed"
                            : ""
                        }
                      >
                        <Search className="mr-2 h-4 w-4" />
                        Queue Triaging
                        {hasRunningTriaging && (
                          <span className="ml-2 text-xs text-muted-foreground">
                            (running)
                          </span>
                        )}
                      </DropdownMenuItem>
                    );
                  })()}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteTaskCallback?.(row.original.id);
                    }}
                    className="text-destructive focus:text-destructive"
                  >
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      );
    },
    enableSorting: false,
    enableHiding: false,
  },
];

export function getSortableColumns(): ColumnDef<Task>[] {
  return tasksColumns
    .filter((column: any) => column.accessorKey !== "mode")
    .map((column: any) => {
      if (column.id === "actions") {
        return column;
      }

      if (column.sortingFn) {
        return { ...column, enableSorting: true };
      }

      const accessorKey = column.accessorKey;

      if (!accessorKey) {
        return column;
      }

      return {
        ...column,
        enableSorting: true,
        header: ({ column: col }: any) => (
          <DataTableColumnHeader
            column={col}
            title={getColumnTitle(accessorKey)}
          />
        ),
      };
    }) as ColumnDef<Task>[];
}

function getColumnTitle(accessorKey: string): string {
  const titles: Record<string, string> = {
    status: "Status",
    mode: "Mode",
    fuzzer: "Fuzzer",
    binary: "Binary",
    runs: "Runs",
    startTime: "Started",
    completedAt: "Time",
  };
  return (
    titles[accessorKey] ||
    accessorKey.charAt(0).toUpperCase() + accessorKey.slice(1)
  );
}
