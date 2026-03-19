import { useEffect, useState, useRef } from "react";
import { useApiUrl } from "@/context/api-url-context";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Copy, Download, RefreshCw } from "lucide-react";
import { toast } from "sonner";

type AnsiState = {
  bold: boolean;
  colorClass: string;
};

type AnsiSegment = {
  text: string;
  className: string;
};

const DEFAULT_ANSI_STATE: AnsiState = {
  bold: false,
  colorClass: "",
};

const ANSI_COLOR_CLASS: Record<number, string> = {
  30: "text-zinc-800 dark:text-zinc-200",
  31: "text-red-500",
  32: "text-green-500",
  33: "text-yellow-500",
  34: "text-blue-500",
  35: "text-fuchsia-500",
  36: "text-cyan-500",
  37: "text-zinc-100",
  90: "text-zinc-500",
  91: "text-red-400",
  92: "text-green-400",
  93: "text-yellow-400",
  94: "text-blue-400",
  95: "text-fuchsia-400",
  96: "text-cyan-400",
  97: "text-zinc-50",
};

function buildAnsiClassName(state: AnsiState) {
  return [state.bold ? "font-semibold" : "", state.colorClass]
    .filter(Boolean)
    .join(" ");
}

function applyAnsiCodes(state: AnsiState, codes: number[]): AnsiState {
  let nextState = { ...state };
  const normalizedCodes = codes.length > 0 ? codes : [0];

  for (const code of normalizedCodes) {
    if (code === 0) {
      nextState = { ...DEFAULT_ANSI_STATE };
    } else if (code === 1) {
      nextState.bold = true;
    } else if (code === 22) {
      nextState.bold = false;
    } else if (code === 39) {
      nextState.colorClass = "";
    } else if (code in ANSI_COLOR_CLASS) {
      nextState.colorClass = ANSI_COLOR_CLASS[code];
    }
  }

  return nextState;
}

function parseAnsiToSegments(input: string): AnsiSegment[] {
  if (!input) return [];

  const tokenRegex = /(\x1b\[[0-9;]*m|\x1b\[[0-?]*[ -/]*[@-~])/g;
  const segments: AnsiSegment[] = [];

  let ansiState: AnsiState = { ...DEFAULT_ANSI_STATE };
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  const pushSegment = (text: string) => {
    if (!text) return;
    const className = buildAnsiClassName(ansiState);
    const prev = segments[segments.length - 1];
    if (prev && prev.className === className) {
      prev.text += text;
    } else {
      segments.push({ text, className });
    }
  };

  while ((match = tokenRegex.exec(input)) !== null) {
    const token = match[0];
    const tokenIndex = match.index;

    pushSegment(input.slice(lastIndex, tokenIndex));

    if (token.endsWith("m")) {
      const body = token.slice(2, -1);
      const codes = body
        .split(";")
        .filter(Boolean)
        .map((value) => Number(value))
        .filter((value) => Number.isFinite(value));

      ansiState = applyAnsiCodes(ansiState, codes);
    }

    lastIndex = tokenRegex.lastIndex;
  }

  pushSegment(input.slice(lastIndex));
  return segments;
}

interface TaskLogsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  taskId: string | null;
  runNumber: number | null;
  title?: string | null;
  downloadFilename?: string | null;
  logUrl?: string | null;
}

export function TaskLogsDialog({
  open,
  onOpenChange,
  taskId,
  runNumber,
  title,
  downloadFilename,
  logUrl,
}: TaskLogsDialogProps) {
  const [logs, setLogs] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logPath, setLogPath] = useState<string>("");
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const API_URL = useApiUrl();
  const ansiSegments = parseAnsiToSegments(logs);

  const fetchLogs = async () => {
    if (!taskId && !logUrl) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        logUrl || `${API_URL}/api/tasks/logs?task_id=${taskId}`,
      );
      const data = await response.json();

      if (response.ok) {
        setLogs(data.content || "");
        setLogPath(data.path || "");
      } else {
        setError(data.error || "Failed to load logs");
        setLogs("");
      }
    } catch (err) {
      setError("Failed to fetch logs");
      console.error("Error fetching logs:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (open && (taskId || logUrl)) {
      fetchLogs();
    }
  }, [open, taskId, logUrl]);

  useEffect(() => {
    if (logs && scrollAreaRef.current) {
      const scrollContainer = scrollAreaRef.current.querySelector(
        "[data-radix-scroll-area-viewport]",
      );
      if (scrollContainer) {
        scrollContainer.scrollTop = scrollContainer.scrollHeight;
      }
    }
  }, [logs]);

  const handleCopy = () => {
    navigator.clipboard.writeText(logs);
    toast.success("Logs copied to clipboard");
  };

  const handleDownload = () => {
    const blob = new Blob([logs], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download =
      downloadFilename ||
      (runNumber !== null ? `log-${runNumber}.log` : "log.txt");
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Log file downloaded");
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="!w-[95vw] !max-w-[1400px] h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {title ||
              (runNumber !== null
                ? `Task Logs - Run #${runNumber}`
                : "Task Logs")}
          </DialogTitle>
          <DialogDescription className="font-mono text-xs">
            {logPath}
          </DialogDescription>
        </DialogHeader>

        <div className="flex gap-2 pb-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchLogs}
            disabled={loading}
          >
            <RefreshCw
              className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            disabled={!logs || loading}
          >
            <Copy className="h-4 w-4 mr-2" />
            Copy
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleDownload}
            disabled={!logs || loading}
          >
            <Download className="h-4 w-4 mr-2" />
            Download
          </Button>
        </div>

        <div className="flex-1 min-h-0">
          {loading ? (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              <div className="flex items-center gap-2">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary"></div>
                <span>Loading logs...</span>
              </div>
            </div>
          ) : error ? (
            <div className="flex items-center justify-center h-full text-destructive">
              <div className="text-center space-y-2">
                <p className="font-semibold">Error Loading Logs</p>
                <p className="text-sm">{error}</p>
              </div>
            </div>
          ) : logs ? (
            <ScrollArea
              ref={scrollAreaRef}
              className="h-full rounded-md border bg-muted/30"
            >
              <pre className="p-4 text-xs font-mono whitespace-pre-wrap break-words">
                {ansiSegments.map((segment, index) => (
                  <span key={index} className={segment.className || undefined}>
                    {segment.text}
                  </span>
                ))}
              </pre>
            </ScrollArea>
          ) : (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              <p>No logs available</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
