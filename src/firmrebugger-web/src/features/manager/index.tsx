import { useState, useEffect } from "react";
import { Header } from "@/components/layout/header";
import { Main } from "@/components/layout/main";
import { TasksDialogs } from "./components/tasks-dialogs";
import { TasksProvider } from "./components/tasks-provider";
import { TasksTable } from "./components/tasks-table";
import { CpuMonitor } from "./components/cpu-monitor";
import { type Task } from "./data/schema";
import { FileCheck, CircleAlert, LoaderCircle } from "lucide-react";

function toDateOrUndefined(value: unknown): Date | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? undefined : value;
  }

  if (typeof value === "number") {
    const numericValue = Number.isFinite(value) ? value : NaN;
    if (Number.isNaN(numericValue)) return undefined;
    const milliseconds =
      Math.abs(numericValue) < 1e11 ? numericValue * 1000 : numericValue;
    const date = new Date(milliseconds);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return undefined;

    const asNumber = Number(trimmed);
    if (!Number.isNaN(asNumber)) {
      const milliseconds =
        Math.abs(asNumber) < 1e11 ? asNumber * 1000 : asNumber;
      const dateFromNumber = new Date(milliseconds);
      if (!Number.isNaN(dateFromNumber.getTime())) {
        return dateFromNumber;
      }
    }

    const dateFromString = new Date(trimmed);
    return Number.isNaN(dateFromString.getTime()) ? undefined : dateFromString;
  }

  return undefined;
}

export function Manager() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const API_URL = import.meta.env.VITE_API_URL || "";

  const applyJobs = (jobs: any[]) => {
    setTasks((prevTasks) => {
      const formattedTasks: Task[] = jobs.map((job: any, index: number) => {
        const existingTask = prevTasks.find((t) => t.id === job.id);
        const normalizedStatus =
          job.status === "error" ? "errored" : job.status;
        const createdAt = toDateOrUndefined(job.createdAt) ?? new Date();
        const startTime = toDateOrUndefined(job.startedAt) ?? createdAt;

        return {
          id: job.id,
          mode: job.mode,
          benchmark: job.benchmark || "FirmBench",
          fuzzer: job.fuzzer,
          binary: job.binary,
          runs: job.runs,
          time: job.time,
          output_dir: job.output_dir || "",
          status: normalizedStatus || "queued",
          progress: job.progress || 0,
          elapsedTime: job.elapsedTime || 0,
          createdAt,
          startTime,
          completedAt: toDateOrUndefined(job.completedAt),
          queuePosition: index,
          autoQueueTriaging:
            existingTask?.autoQueueTriaging ?? job.autoQueueTriaging ?? true,
          triaged: job.triaged ?? false,
        };
      });
      return formattedTasks;
    });
  };

  const fetchJobs = async () => {
    try {
      const response = await fetch(`${API_URL}/api/jobs/list`);
      const data = await response.json();

      if (data.jobs) {
        applyJobs(data.jobs);
      } else {
        console.log("No jobs in response");
      }
    } catch (error) {
      console.error("Failed to fetch jobs:", error);
    }
  };

  useEffect(() => {
    let fallbackInterval: ReturnType<typeof setInterval> | null = null;
    const eventSource = new EventSource(`${API_URL}/api/jobs/stream`);

    const ensureFallbackPolling = () => {
      if (fallbackInterval) return;
      fallbackInterval = setInterval(fetchJobs, 5000);
    };

    eventSource.addEventListener("jobs", (event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data);
        if (payload.jobs) {
          applyJobs(payload.jobs);
          // Stream is healthy — cancel any active fallback polling
          if (fallbackInterval) {
            clearInterval(fallbackInterval);
            fallbackInterval = null;
          }
        }
      } catch (error) {
        console.error("Failed to parse jobs stream payload:", error);
      }
    });

    eventSource.onerror = (error) => {
      console.error(
        "Jobs stream disconnected, enabling fallback polling:",
        error,
      );
      ensureFallbackPolling();
    };

    return () => {
      eventSource.close();
      if (fallbackInterval) {
        clearInterval(fallbackInterval);
      }
    };
  }, []);

  const activeTasks = tasks.filter(
    (task) =>
      task.status === "running" ||
      task.status === "queued" ||
      task.status === "stopping",
  );
  const finishedTasks = tasks.filter(
    (task) =>
      task.mode !== "Triaging" &&
      (task.status === "completed" ||
        task.status === "stopped" ||
        task.status === "errored"),
  );

  return (
    <TasksProvider tasks={tasks} setTasks={setTasks}>
      <Header fixed />

      <Main className="flex flex-1 flex-col gap-4 sm:gap-6">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">Job Manager</h2>
            <p className="text-muted-foreground">
              Manage fuzzing and triaging jobs.
            </p>
          </div>
        </div>

        <CpuMonitor />

        <div className="flex flex-col gap-6">
          <div>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-xl font-semibold">Active Jobs</h3>
              <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                <div className="flex items-center gap-1.5">
                  <FileCheck className="h-3.5 w-3.5 text-blue-500" />
                  <span>Triaged</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <CircleAlert className="h-3.5 w-3.5 text-red-500" />
                  <span>Triaging failed</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <LoaderCircle className="h-3.5 w-3.5 text-amber-500" />
                  <span>Triaging in progress</span>
                </div>
              </div>
            </div>
            <TasksTable data={activeTasks} allTasks={tasks} />
          </div>

          {finishedTasks.length > 0 && (
            <div>
              <h3 className="text-xl font-semibold mb-3">Finished Jobs</h3>
              <TasksTable
                data={finishedTasks}
                showCreateButton={false}
                enableColumnSorting={true}
                allTasks={tasks}
                isFinishedJobs={true}
              />
            </div>
          )}
        </div>
      </Main>

      <TasksDialogs />
    </TasksProvider>
  );
}
