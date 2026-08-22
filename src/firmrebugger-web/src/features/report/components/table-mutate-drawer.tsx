import { z } from "zod";
import { useState, useEffect } from "react";
import { useApiUrl } from "@/context/api-url-context";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Check, ChevronDown, ChevronRight, X } from "lucide-react";
import { showSubmittedData } from "@/lib/show-submitted-data";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import {
  Form,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormDescription,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

type ReportDetail = {
  reportPath: string;
  benchmark: string;
  binary: string;
  fuzzer: string;
  run_name: string;
  mtime: number;
};

type TableMutateDrawerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  benchmark: string;
  onSuccess?: (data?: any, query?: TableForm) => void;
  initialValues?: Partial<TableForm>;
  onSelectionsChange?: (values: TableForm) => void;
};

const formSchema = z.object({
  fuzzer: z.array(z.string()).min(1, "At least one fuzzer is required."),
  selectedReports: z
    .record(z.string(), z.record(z.string(), z.string()))
    .refine((reports) => {
      return Object.keys(reports).length > 0;
    }, "At least one binary is required."),
});
export type TableForm = z.infer<typeof formSchema>;

export function TableMutateDrawer({
  open,
  onOpenChange,
  benchmark,
  onSuccess,
  initialValues,
  onSelectionsChange,
}: TableMutateDrawerProps) {
  const [fuzzers, setFuzzers] = useState<string[]>([]);
  const [loadingFuzzers, setLoadingFuzzers] = useState(false);
  const [reportDetails, setReportDetails] = useState<ReportDetail[]>([]);
  const [benchmarkBinaries, setBenchmarkBinaries] = useState<string[]>([]);
  const [reportDurations, setReportDurations] = useState<
    Record<string, number | null>
  >({});
  const [loadingReports, setLoadingReports] = useState(false);
  const [binarySearch, setBinarySearch] = useState("");
  const [expandedBinaries, setExpandedBinaries] = useState<Set<string>>(
    new Set(),
  );
  const [pendingBinarySelections, setPendingBinarySelections] = useState<
    Set<string>
  >(new Set());
  const API_URL = useApiUrl();

  const reportsByBinaryAndFuzzer: Record<string, Record<string, string[]>> = {};
  const reportDetailsByPath: Record<string, ReportDetail> = {};

  reportDetails.forEach((detail) => {
    reportDetailsByPath[detail.reportPath] = detail;

    if (!reportsByBinaryAndFuzzer[detail.binary]) {
      reportsByBinaryAndFuzzer[detail.binary] = {};
    }
    if (!reportsByBinaryAndFuzzer[detail.binary][detail.fuzzer]) {
      reportsByBinaryAndFuzzer[detail.binary][detail.fuzzer] = [];
    }
    reportsByBinaryAndFuzzer[detail.binary][detail.fuzzer].push(
      detail.reportPath,
    );
  });

  const reportBinaries = Object.keys(reportsByBinaryAndFuzzer).sort(
    (a, b) => a.localeCompare(b),
  );
  const allBinaries = Array.from(
    new Set([...benchmarkBinaries, ...reportBinaries]),
  ).sort((a, b) => a.localeCompare(b));
  const binariesWithoutReports = allBinaries.filter(
    (binary) => !reportsByBinaryAndFuzzer[binary],
  );
  const reportFolders = Array.from(
    reportDetails.reduce((folders, detail) => {
      const outputFolder = detail.run_name || "Unknown output folder";
      const binaries = folders.get(outputFolder) || new Set<string>();
      binaries.add(detail.binary);
      folders.set(outputFolder, binaries);
      return folders;
    }, new Map<string, Set<string>>()),
  )
    .map(([outputFolder, binaries]) => ({
      outputFolder,
      binaries: Array.from(binaries).sort((a, b) => a.localeCompare(b)),
    }))
    .sort((a, b) => a.outputFolder.localeCompare(b.outputFolder));

  useEffect(() => {
    const fetchFuzzers = async () => {
      setLoadingFuzzers(true);
      try {
        const response = await fetch(`${API_URL}/api/fuzzers/list`);
        const data = await response.json();

        if (data.items) {
          const fuzzerNames = data.items
            .filter((item: any) => item.type === "directory")
            .map((item: any) => item.name);
          setFuzzers(fuzzerNames);
        }
      } catch (error) {
        console.error("Failed to fetch fuzzers:", error);
      } finally {
        setLoadingFuzzers(false);
      }
    };

    fetchFuzzers();
  }, []);

  const form = useForm<TableForm>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      fuzzer: [],
      selectedReports: {},
    },
  });

  useEffect(() => {
    if (open && initialValues) {
      try {
        form.reset({
          fuzzer: initialValues.fuzzer || [],
          selectedReports: initialValues.selectedReports || {},
        });
      } catch (e) {
        // ignore
      }
      try {
        const initialFuzzers = (initialValues.fuzzer || []).filter(
          (v): v is string => !!v,
        );
        fetchReportsFor(initialFuzzers);
      } catch (e) {
        // ignore
      }
    }
  }, [open, initialValues]);

  useEffect(() => {
    if (!onSelectionsChange) return;
    const subscription = form.watch((value) => {
      try {
        onSelectionsChange(value as TableForm);
      } catch (e) {
        // ignore
      }
    });
    return () => subscription.unsubscribe();
  }, [form, onSelectionsChange]);

  const selectedFuzzers = form.watch("fuzzer");

  const onSubmit = async (data: TableForm) => {
    console.log("TableMutateDrawer onSubmit called with data:", data);
    const selectedFuzzers = Array.isArray(data.fuzzer)
      ? data.fuzzer
      : [data.fuzzer];

    const selectedReportPaths: string[] = [];
    Object.values(data.selectedReports).forEach((fuzzerReports) => {
      Object.values(fuzzerReports).forEach((reportPath) => {
        selectedReportPaths.push(reportPath);
      });
    });

    try {
      console.log("TableMutateDrawer submitting to API with", {
        benchmark,
        selectedFuzzers,
        selectedReportPaths,
        selectedBinaries: Object.keys(data.selectedReports),
      });
      const response = await fetch(`${API_URL}/api/table/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          benchmark,
          fuzzers: selectedFuzzers,
          report_paths: selectedReportPaths,
          selected_binaries: Object.keys(data.selectedReports),
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to generate table");
      }

      const result = await response.json();
      console.log("Table generated successfully:", result);

      if (onSelectionsChange) {
        try {
          onSelectionsChange(data);
        } catch (e) {}
      }

      if (onSuccess) {
        console.log("Calling onSuccess with result and query:", result, data);
        onSuccess(result, data);
      }

      onOpenChange(false);

      showSubmittedData(
        { ...data, benchmark, count: selectedReportPaths.length },
        `Generated table for ${Object.keys(data.selectedReports).length} binaries × ${selectedFuzzers.length} fuzzers - Benchmark: ${benchmark}`,
      );
    } catch (error) {
      console.error("Error generating table:", error);
      form.setError("selectedReports", {
        type: "manual",
        message:
          error instanceof Error ? error.message : "Failed to generate table",
      });
    }
  };

  const fetchReportsFor = async (selectedFuzzers: string[]) => {
    if (!selectedFuzzers || selectedFuzzers.length === 0) {
      setReportDetails([]);
      setBenchmarkBinaries([]);
      setReportDurations({});
      return;
    }

    setLoadingReports(true);
    try {
      const reportsResponse = await fetch(`${API_URL}/api/get_reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          benchmark: benchmark,
          // Fetch every discovered report. The backend's filtered response
          // omits binaries when one selected fuzzer has no report, while the
          // drawer needs to show that missing-fuzzer state itself.
          fuzzers: [],
        }),
      });

      const reportsData = await reportsResponse.json();

      const details: ReportDetail[] = reportsData.report_details || [];
      const durations = reportsData.report_durations || {};

      setReportDetails(details);
      setBenchmarkBinaries(reportsData.binaries || []);
      setReportDurations(durations);
    } catch (error) {
      console.error("Failed to fetch reports:", error);
      setReportDetails([]);
      setBenchmarkBinaries([]);
      setReportDurations({});
    } finally {
      setLoadingReports(false);
    }
  };

  useEffect(() => {
    const subscription = form.watch((value, { name }) => {
      if (name === "fuzzer") {
        const selectedFuzzers = (value.fuzzer || []).filter(
          (v): v is string => !!v,
        );
        fetchReportsFor(selectedFuzzers);
      }
    });

    return () => subscription.unsubscribe();
  }, [benchmark, form]);

  useEffect(() => {
    const subscription = form.watch((values, { name }) => {
      if (name === "fuzzer") {
        const selectedFuzzers = values.fuzzer || [];
        const currentReports = form.getValues("selectedReports") || {};

        const updatedReports = Object.fromEntries(
          Object.entries(currentReports).map(([binary, fuzzerReports]) => [
            binary,
            Object.fromEntries(
              Object.entries(fuzzerReports).filter(([fuzzer]) =>
                selectedFuzzers.includes(fuzzer),
              ),
            ),
          ]),
        );

        form.setValue("selectedReports", updatedReports);
      }
    });

    return () => subscription.unsubscribe();
  }, [form]);

  const toggleBinaryExpansion = (binary: string) => {
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

  const getReportLabel = (reportPath: string) => {
    const outputName = reportDetailsByPath[reportPath]?.run_name || reportPath;

    const durationSeconds = reportDurations[reportPath];
    if (
      durationSeconds === null ||
      durationSeconds === undefined ||
      Number.isNaN(Number(durationSeconds))
    ) {
      return outputName;
    }

    const totalSeconds = Math.max(0, Number(durationSeconds));
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = Math.floor(totalSeconds % 60);

    let durationLabel = "";
    if (hours > 0) {
      durationLabel = `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
      durationLabel = `${minutes}m`;
    } else {
      durationLabel = `${seconds}s`;
    }

    return `${outputName} (${durationLabel})`;
  };

  const getReportTimestamp = (reportPath: string): number => {
    return (reportDetailsByPath[reportPath]?.mtime || 0) * 1000;
  };

  const getOutputFolderName = (reportPath: string): string => {
    return reportDetailsByPath[reportPath]?.run_name || reportPath;
  };

  const folderBinaryKey = (outputFolder: string, binary: string) =>
    `${outputFolder}\u0000${binary}`;

  const togglePendingBinary = (outputFolder: string, binary: string) => {
    const key = folderBinaryKey(outputFolder, binary);
    setPendingBinarySelections((current) => {
      const updated = new Set(current);
      if (updated.has(key)) {
        updated.delete(key);
      } else {
        updated.add(key);
      }
      return updated;
    });
  };

  const selectFolderReports = (
    binaries: string[],
    outputFolder: string,
  ) => {
    const currentValue = form.getValues("selectedReports") || {};
    const newValue = { ...currentValue };

    const selectedFuzzerList = selectedFuzzers || [];
    if (selectedFuzzerList.length === 0 || binaries.length === 0) {
      return;
    }

    binaries.forEach((binary) => {
      // Applying a folder replaces this binary's previous choices. Fuzzers
      // without a report intentionally remain absent and render as N/A.
      newValue[binary] = {};

      selectedFuzzerList.forEach((fuzzer) => {
        const matchingReports = (
          reportsByBinaryAndFuzzer[binary]?.[fuzzer] || []
        ).filter((path) => getOutputFolderName(path) === outputFolder);

        if (matchingReports.length > 0) {
          newValue[binary][fuzzer] = matchingReports.reduce(
            (latest, current) =>
              getReportTimestamp(current) > getReportTimestamp(latest)
                ? current
                : latest,
          );
        }
      });
    });

    form.clearErrors("selectedReports");
    form.setValue("selectedReports", newValue);
    setPendingBinarySelections((current) => {
      const updated = new Set(current);
      binaries.forEach((binary) =>
        updated.delete(folderBinaryKey(outputFolder, binary)),
      );
      return updated;
    });
  };

  return (
    <Sheet
      open={open}
      onOpenChange={(v) => {
        if (!v) {
          setPendingBinarySelections(new Set());
        }
        onOpenChange(v);
      }}
    >
      <SheetContent className="flex flex-col">
        <SheetHeader className="text-start">
          <SheetTitle>Generate Table</SheetTitle>
          <SheetDescription>
            Generate a table for {benchmark}. Click Submit when you are done.
          </SheetDescription>
        </SheetHeader>

        <Form {...form}>
          <form
            id="table-form"
            onSubmit={form.handleSubmit(onSubmit, (errors) => {
              console.warn("TableMutateDrawer validation errors:", errors);
            })}
            className="flex-1 space-y-6 overflow-y-auto px-4"
          >
            <FormField
              control={form.control}
              name="fuzzer"
              render={({ field }) => (
                <FormItem>
                  <div className="flex items-center justify-between">
                    <FormLabel className="flex items-center gap-2">
                      Fuzzers
                      <Badge variant="secondary" className="text-xs">
                        {field.value?.length || 0} selected
                      </Badge>
                    </FormLabel>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      className="text-xs h-7 px-2 ml-2"
                      onClick={() => field.onChange([])}
                      disabled={!field.value?.length}
                    >
                      Clear All
                    </Button>
                  </div>
                  <FormDescription className="text-xs">
                    Select one or more fuzzers (click to select multiple)
                  </FormDescription>
                  <div className="border rounded-md p-3 max-h-60 overflow-y-auto">
                    {loadingFuzzers ? (
                      <p className="text-sm text-muted-foreground">
                        Loading fuzzers...
                      </p>
                    ) : fuzzers.length > 0 ? (
                      <div className="space-y-2">
                        {fuzzers.map((fuzzer) => {
                          const isSelected = field.value?.includes(fuzzer);
                          return (
                            <div
                              key={fuzzer}
                              className={`flex items-center space-x-2 p-2 rounded-md transition-colors ${
                                isSelected
                                  ? "bg-primary/10 border border-primary"
                                  : "border border-transparent"
                              }`}
                            >
                              <Checkbox
                                checked={isSelected}
                                onCheckedChange={(checked) => {
                                  const currentValue = field.value || [];
                                  const newValue = checked
                                    ? [...currentValue, fuzzer]
                                    : currentValue.filter((v) => v !== fuzzer);
                                  field.onChange(newValue);
                                }}
                              />
                              <label
                                className="flex-1 cursor-pointer text-sm font-medium"
                                onClick={() => {
                                  const currentValue = field.value || [];
                                  const newValue = isSelected
                                    ? currentValue.filter((v) => v !== fuzzer)
                                    : [...currentValue, fuzzer];
                                  field.onChange(newValue);
                                }}
                              >
                                {fuzzer}
                              </label>
                              {isSelected && (
                                <Check className="h-4 w-4 text-primary" />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No fuzzers found
                      </p>
                    )}
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="selectedReports"
              render={({ field }) => {
                const filteredReportFolders = reportFolders
                  .map((folder) => ({
                    ...folder,
                    binaries: folder.binaries.filter((binary) =>
                      binary
                        .toLowerCase()
                        .includes(binarySearch.toLowerCase()),
                    ),
                  }))
                  .filter((folder) => folder.binaries.length > 0);

                const filteredBinaries = filteredReportFolders.flatMap(
                  (folder) => folder.binaries,
                );
                const filteredBinariesWithoutReports =
                  binariesWithoutReports.filter((binary) =>
                    binary.toLowerCase().includes(binarySearch.toLowerCase()),
                  );
                const hasFilteredBinaries =
                  filteredBinaries.length > 0 ||
                  filteredBinariesWithoutReports.length > 0;

                return (
                  <FormItem>
                    <div className="flex items-center justify-between">
                      <FormLabel className="flex items-center gap-2">
                        Binaries & Reports
                        <Badge variant="secondary" className="text-xs">
                          {Object.keys(field.value || {}).length} binaries
                        </Badge>
                      </FormLabel>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="text-xs h-7 px-2 ml-2"
                        onClick={() => form.setValue("selectedReports", {})}
                        disabled={Object.keys(field.value || {}).length === 0}
                      >
                        Clear All
                      </Button>
                    </div>
                    <FormDescription className="text-xs">
                      Reports are organized by output folder, then binary.
                      Toggle specific binaries and click "Select", or click
                      "Select All" when none are toggled. Expand a binary to
                      adjust individual reports.
                      Binaries without reports can still be included as N/A.
                    </FormDescription>
                    {allBinaries.length > 0 && (
                      <Input
                        type="text"
                        placeholder="Search binaries..."
                        value={binarySearch}
                        onChange={(e) => setBinarySearch(e.target.value)}
                        className="mb-2"
                      />
                    )}
                    <div className="border rounded-md p-3 max-h-96 overflow-y-auto">
                      {loadingReports ? (
                        <p className="text-sm text-muted-foreground">
                          Loading reports...
                        </p>
                      ) : hasFilteredBinaries ? (
                        <div className="space-y-3">
                          {filteredReportFolders.map(
                            ({ outputFolder, binaries }) => {
                              const toggledBinaries = binaries.filter((binary) =>
                                pendingBinarySelections.has(
                                  folderBinaryKey(outputFolder, binary),
                                ),
                              );
                              const binariesToSelect =
                                toggledBinaries.length > 0
                                  ? toggledBinaries
                                  : binaries;

                              return (
                              <div
                                key={outputFolder}
                                className="rounded-md border bg-muted/20 p-2"
                              >
                                <div className="mb-2 flex items-center justify-between gap-2">
                                  <div className="flex min-w-0 items-center gap-2 text-xs font-semibold text-muted-foreground">
                                    <span>Output folder</span>
                                    <code className="truncate rounded bg-background px-1.5 py-0.5 font-mono text-foreground">
                                      {outputFolder}
                                    </code>
                                  </div>
                                  <Button
                                    type="button"
                                    size="sm"
                                    variant="outline"
                                    className="h-7 shrink-0 px-2 text-xs"
                                    onClick={() =>
                                      selectFolderReports(
                                        binariesToSelect,
                                        outputFolder,
                                      )
                                    }
                                  >
                                    {toggledBinaries.length > 0
                                      ? "Select"
                                      : "Select All"}
                                  </Button>
                                </div>
                                <div className="space-y-1">
                                  {binaries.map((binary) => {
                            const isExpanded = expandedBinaries.has(binary);
                            const isToggled = pendingBinarySelections.has(
                              folderBinaryKey(outputFolder, binary),
                            );
                            const binaryReports = field.value?.[binary] || {};
                            const selectedCount =
                              Object.keys(binaryReports).length;
                            const isComplete =
                              selectedFuzzers?.length > 0 &&
                              selectedCount === selectedFuzzers.length;

                            return (
                              <div key={binary} className="space-y-1">
                                <div
                                  className={`flex items-center space-x-2 p-2 rounded-md transition-colors ${
                                    isComplete
                                      ? "bg-primary/10 border border-primary"
                                      : selectedCount > 0
                                        ? "bg-yellow-50 border border-yellow-300"
                                        : "border border-transparent hover:bg-muted"
                                  }`}
                                >
                                  <Checkbox
                                    checked={isToggled}
                                    aria-label={`Toggle ${binary} for selection`}
                                    onCheckedChange={() =>
                                      togglePendingBinary(outputFolder, binary)
                                    }
                                  />
                                  <div
                                    className="flex items-center space-x-2 flex-1 min-w-0 cursor-pointer"
                                    onClick={() =>
                                      toggleBinaryExpansion(binary)
                                    }
                                  >
                                    {isExpanded ? (
                                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                    ) : (
                                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                                    )}
                                    <span className="flex-1 text-sm font-medium">
                                      {binary}
                                    </span>
                                    <span className="text-xs text-muted-foreground shrink-0">
                                      Details
                                    </span>
                                    <Badge
                                      variant="outline"
                                      className="text-xs shrink-0"
                                    >
                                      {selectedCount}/
                                      {selectedFuzzers?.length || 0}
                                    </Badge>
                                    {isComplete && (
                                      <Check className="h-4 w-4 text-primary shrink-0" />
                                    )}
                                  </div>
                                </div>

                                {isExpanded &&
                                  selectedFuzzers &&
                                  selectedFuzzers.length > 0 && (
                                    <div className="ml-6 space-y-2 py-1">
                                      {selectedFuzzers.map((fuzzer) => {
                                        const reportsForFuzzer = (
                                          reportsByBinaryAndFuzzer[binary]?.[
                                            fuzzer
                                          ] || []
                                        ).filter(
                                          (path) =>
                                            getOutputFolderName(path) ===
                                            outputFolder,
                                        );
                                        const selectedReport =
                                          binaryReports[fuzzer];

                                        if (reportsForFuzzer.length === 0) {
                                          return (
                                            <div
                                              key={fuzzer}
                                              className="p-2 rounded-md bg-muted/30"
                                            >
                                              <div className="text-xs font-medium text-muted-foreground">
                                                {fuzzer}: No reports available
                                              </div>
                                            </div>
                                          );
                                        }

                                        return (
                                          <div
                                            key={fuzzer}
                                            className="border rounded-md p-2 space-y-1"
                                          >
                                            <div className="flex items-center justify-between">
                                              <div className="text-xs font-medium">
                                                {fuzzer}
                                              </div>
                                              {selectedReport && (
                                                <Badge
                                                  variant="secondary"
                                                  className="text-xs"
                                                >
                                                  Selected
                                                </Badge>
                                              )}
                                            </div>
                                            <div className="space-y-1">
                                              {reportsForFuzzer.map(
                                                (reportPath) => {
                                                  const reportLabel =
                                                    getReportLabel(reportPath);
                                                  const isSelected =
                                                    selectedReport ===
                                                    reportPath;

                                                  return (
                                                    <div
                                                      key={reportPath}
                                                      className={`flex items-center justify-between p-1.5 rounded transition-colors cursor-pointer ${
                                                        isSelected
                                                          ? "bg-primary/10 border border-primary"
                                                          : "hover:bg-muted/50"
                                                      }`}
                                                      onClick={() => {
                                                        const newValue = {
                                                          ...field.value,
                                                        };
                                                        if (!newValue[binary]) {
                                                          newValue[binary] = {};
                                                        }

                                                        if (isSelected) {
                                                          delete newValue[
                                                            binary
                                                          ][fuzzer];
                                                          if (
                                                            Object.keys(
                                                              newValue[binary],
                                                            ).length === 0
                                                          ) {
                                                            delete newValue[
                                                              binary
                                                            ];
                                                          }
                                                        } else {
                                                          newValue[binary][
                                                            fuzzer
                                                          ] = reportPath;
                                                        }

                                                        field.onChange(
                                                          newValue,
                                                        );
                                                      }}
                                                    >
                                                      <span className="text-xs">
                                                        {reportLabel}
                                                      </span>
                                                      {isSelected ? (
                                                        <X className="h-3 w-3 text-primary" />
                                                      ) : (
                                                        <div className="h-3 w-3" />
                                                      )}
                                                    </div>
                                                  );
                                                },
                                              )}
                                            </div>
                                          </div>
                                        );
                                      })}
                                    </div>
                                  )}
                              </div>
                                  );
                                })}
                              </div>
                            </div>
                              );
                            },
                        )}
                          {filteredBinariesWithoutReports.length > 0 && (
                            <div className="rounded-md border bg-muted/20 p-2">
                              <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-muted-foreground">
                                <span>No report output</span>
                                <Badge variant="outline" className="text-xs">
                                  N/A
                                </Badge>
                              </div>
                              <div className="space-y-1">
                                {filteredBinariesWithoutReports.map((binary) => {
                                  const isSelected = Object.prototype.hasOwnProperty.call(
                                    field.value || {},
                                    binary,
                                  );
                                  return (
                                    <button
                                      key={binary}
                                      type="button"
                                      className={`flex w-full items-center gap-2 rounded-md border p-2 text-left transition-colors ${
                                        isSelected
                                          ? "border-primary bg-primary/10"
                                          : "border-transparent hover:bg-muted"
                                      }`}
                                      onClick={() => {
                                        const newValue = { ...(field.value || {}) };
                                        if (isSelected) {
                                          delete newValue[binary];
                                        } else {
                                          newValue[binary] = {};
                                        }
                                        field.onChange(newValue);
                                      }}
                                    >
                                      <Checkbox checked={isSelected} />
                                      <span className="flex-1 text-sm font-medium">
                                        {binary}
                                      </span>
                                      <Badge variant="secondary" className="text-xs">
                                        N/A
                                      </Badge>
                                    </button>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : allBinaries.length > 0 ? (
                        <p className="text-sm text-muted-foreground">
                          No binaries match your search
                        </p>
                      ) : (
                        <p className="text-sm text-muted-foreground">
                          {form.watch("fuzzer")?.length > 0
                            ? "No binaries available for the selected benchmark"
                            : "Please select at least one fuzzer first"}
                        </p>
                      )}
                    </div>
                    <FormMessage />
                  </FormItem>
                );
              }}
            />
          </form>
        </Form>

        <SheetFooter className="gap-2">
          <SheetClose asChild>
            <Button
              variant="outline"
              onClick={() => {
                form.reset();
                setBinarySearch("");
                setExpandedBinaries(new Set());
                setPendingBinarySelections(new Set());
              }}
            >
              Cancel
            </Button>
          </SheetClose>
          <Button type="submit" form="table-form">
            Submit
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
