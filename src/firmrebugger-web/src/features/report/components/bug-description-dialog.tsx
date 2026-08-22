import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import { useTheme } from "next-themes";
import { PrismLight as SyntaxHighlighter } from "react-syntax-highlighter";
import c from "react-syntax-highlighter/dist/esm/languages/prism/c";
import { oneDark, oneLight } from "react-syntax-highlighter/dist/esm/styles/prism";
import { useApiUrl } from "@/context/api-url-context";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface RavenEntry {
  benchmark: string;
  binary: string;
  reported_id: string;
  code: string;
}

interface BugAnalysisEntry {
  bug_id: string;
  binary: string;
  mcu: string;
  cwes: string[];
  cves: string[];
  benchmarks: string[];
  status: "confirmed" | "false_positive" | "needs_triage";
  summary: string;
  body: string;
  ravens: RavenEntry[];
}

SyntaxHighlighter.registerLanguage("c", c);

interface BugDescriptionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  bugId: string | null;
}

export function BugDescriptionDialog({
  open,
  onOpenChange,
  bugId,
}: BugDescriptionDialogProps) {
  const API_URL = useApiUrl();
  const { resolvedTheme } = useTheme();
  const isFalsePositive = bugId?.startsWith("FP_") ?? false;
  // FP_-prefixed IDs (e.g. FP_FRB01) are a fuzzer's false-positive-flagged
  // variant of an underlying documented bug — the bug_analysis registry
  // files it under the bare id (FRB01.md), so strip the prefix to look it up.
  const lookupId = bugId?.replace(/^FP_/, "") ?? null;

  type FetchState =
    | { status: "idle" }
    | { status: "loading" }
    | { status: "found"; entry: BugAnalysisEntry }
    | { status: "not_found" }
    | { status: "error"; message: string };

  const [state, setState] = useState<FetchState>({ status: "idle" });

  useEffect(() => {
    if (!open || !lookupId) {
      return;
    }

    let cancelled = false;
    setState({ status: "loading" });

    fetch(`${API_URL}/api/bug_analysis/${encodeURIComponent(lookupId)}`)
      .then(async (res) => {
        if (cancelled) return;
        if (res.status === 404) {
          setState({ status: "not_found" });
          return;
        }
        const json = await res.json();
        if (!res.ok) {
          setState({
            status: "error",
            message: json.error || "Failed to load bug analysis",
          });
          return;
        }
        setState({ status: "found", entry: json });
      })
      .catch((err) => {
        console.error("Failed to fetch bug analysis:", err);
        if (!cancelled) {
          setState({ status: "error", message: "Failed to load bug analysis" });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, lookupId, API_URL]);

  const entry = state.status === "found" ? state.entry : null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="!w-[95vw] !max-w-[900px] max-h-[85vh] flex flex-col">
        {entry ? (
          <Tabs defaultValue="description" className="contents">
            <TabsList
              className="absolute bottom-full left-6 z-10 h-8 items-end gap-1 rounded-none bg-transparent p-0"
              style={{ marginBottom: -1 }}
            >
              <TabsTrigger
                value="description"
                className="h-8 rounded-t-md rounded-b-none border border-border border-b-0 px-3 text-xs font-medium shadow-none data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-none data-[state=inactive]:bg-muted data-[state=inactive]:text-muted-foreground"
              >
                Description
              </TabsTrigger>
              <TabsTrigger
                value="raven"
                className="h-8 rounded-t-md rounded-b-none border border-border border-b-0 px-3 text-xs font-medium shadow-none data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-none data-[state=inactive]:bg-muted data-[state=inactive]:text-muted-foreground"
              >
                Raven{entry.ravens.length > 1 ? ` (${entry.ravens.length})` : ""}
              </TabsTrigger>
            </TabsList>

            <DialogHeader>
              <DialogTitle
                className="font-mono"
                style={{ color: isFalsePositive ? "#c46464" : "#4e79a7" }}
              >
                {bugId}
              </DialogTitle>
              <DialogDescription>{entry.summary || "Bug analysis"}</DialogDescription>
            </DialogHeader>

            <div className="flex-1 min-h-0 overflow-y-auto">
              <TabsContent value="description" className="space-y-4">
                <div className="flex flex-wrap items-center gap-1.5">
                  {entry.status === "needs_triage" && (
                    <Badge variant="secondary">Needs triage</Badge>
                  )}
                  {entry.cwes.map((cwe) => (
                    <Badge key={cwe} variant="outline">
                      {cwe}
                    </Badge>
                  ))}
                  {entry.cves.map((cve) => (
                    <Badge key={cve} variant="outline">
                      {cve}
                    </Badge>
                  ))}
                </div>

                <p className="text-xs text-muted-foreground">
                  {entry.binary} &middot; {entry.mcu} &middot;{" "}
                  {entry.benchmarks.join(", ")}
                </p>

                <div className="text-sm leading-relaxed">
                  <ReactMarkdown
                    components={{
                      h1: ({ children }) => (
                        <h3 className="text-base font-semibold mt-4 mb-2 first:mt-0">
                          {children}
                        </h3>
                      ),
                      h2: ({ children }) => (
                        <h4 className="text-sm font-semibold mt-4 mb-2 first:mt-0">
                          {children}
                        </h4>
                      ),
                      h3: ({ children }) => (
                        <h5 className="text-sm font-semibold mt-3 mb-1.5 first:mt-0">
                          {children}
                        </h5>
                      ),
                      p: ({ children }) => (
                        <p className="mb-3 last:mb-0">{children}</p>
                      ),
                      a: ({ children, href }) => (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary underline underline-offset-2 hover:opacity-75"
                        >
                          {children}
                        </a>
                      ),
                      code: ({ children }) => (
                        <code className="bg-muted rounded px-1 py-0.5 text-xs font-mono">
                          {children}
                        </code>
                      ),
                      ul: ({ children }) => (
                        <ul className="list-disc pl-5 mb-3 space-y-1">
                          {children}
                        </ul>
                      ),
                      ol: ({ children }) => (
                        <ol className="list-decimal pl-5 mb-3 space-y-1">
                          {children}
                        </ol>
                      ),
                    }}
                  >
                    {entry.body}
                  </ReactMarkdown>
                </div>
              </TabsContent>

              <TabsContent value="raven" className="space-y-4">
                {entry.ravens.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No raven found in bug_descriptor.c for this bug.
                  </p>
                ) : (
                  entry.ravens.map((raven, i) => (
                    <div key={i} className="space-y-1.5">
                      <p className="text-xs text-muted-foreground font-mono">
                        {raven.benchmark}/{raven.binary} &middot;{" "}
                        {raven.reported_id}
                      </p>
                      <div className="overflow-x-auto rounded-md border">
                        <SyntaxHighlighter
                          language="c"
                          style={resolvedTheme === "dark" ? oneDark : oneLight}
                          customStyle={{
                            margin: 0,
                            background: "transparent",
                            fontSize: "0.75rem",
                            padding: "0.75rem",
                          }}
                          codeTagProps={{
                            style: { fontFamily: "inherit" },
                          }}
                        >
                          {raven.code}
                        </SyntaxHighlighter>
                      </div>
                    </div>
                  ))
                )}
              </TabsContent>
            </div>
          </Tabs>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle
                className="font-mono"
                style={{ color: isFalsePositive ? "#c46464" : "#4e79a7" }}
              >
                {bugId}
              </DialogTitle>
              <DialogDescription>Bug analysis</DialogDescription>
            </DialogHeader>

            <div className="flex-1 min-h-0 overflow-y-auto">
              {state.status === "loading" ? (
                <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-primary" />
                  Loading bug analysis...
                </div>
              ) : state.status === "error" ? (
                <p className="text-sm text-destructive">{state.message}</p>
              ) : state.status === "not_found" ? (
                <p className="text-sm text-muted-foreground">
                  No bug analysis entry has been written for {lookupId} yet.
                </p>
              ) : null}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
