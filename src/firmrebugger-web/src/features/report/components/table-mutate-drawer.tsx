import { z } from "zod";
import { useState, useEffect } from "react";
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
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

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
    }, "At least one binary with reports selected is required."),
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
  const [validFuzzers, setValidFuzzers] = useState<string[]>([]);
  const [reportPaths, setReportPaths] = useState<string[]>([]);
  const [reportDurations, setReportDurations] = useState<Record<string, number | null>>({});
  const [availableBinaries, setAvailableBinaries] = useState<string[]>([]);
  const [unavailableReasons, setUnavailableReasons] = useState<Record<string, string>>({});
  const [loadingReports, setLoadingReports] = useState(false);
  const [binarySearch, setBinarySearch] = useState("");
  const [expandedBinaries, setExpandedBinaries] = useState<Set<string>>(
    new Set(),
  );
  const API_URL = import.meta.env.VITE_API_URL || "";

  const reportsByBinaryAndFuzzer: Record<string, Record<string, string[]>> = {};

  const extractBinaryAndFuzzer = (reportPath: string) => {
    const parts = reportPath.split("/");
    const benchmarkIndex = parts.indexOf(benchmark);
    const fuzzersIndex = parts.indexOf("fuzzers");

    if (
      benchmarkIndex !== -1 &&
      fuzzersIndex !== -1 &&
      benchmarkIndex + 1 < parts.length &&
      fuzzersIndex + 1 < parts.length
    ) {
      return {
        binaryName: parts[benchmarkIndex + 1],
        fuzzerName: parts[fuzzersIndex + 1],
      };
    }
    return null;
  };

  reportPaths.forEach((reportPath) => {
    const extracted = extractBinaryAndFuzzer(reportPath);
    if (extracted) {
      const { binaryName, fuzzerName } = extracted;

      if (!reportsByBinaryAndFuzzer[binaryName]) {
        reportsByBinaryAndFuzzer[binaryName] = {};
      }
      if (!reportsByBinaryAndFuzzer[binaryName][fuzzerName]) {
        reportsByBinaryAndFuzzer[binaryName][fuzzerName] = [];
      }
      reportsByBinaryAndFuzzer[binaryName][fuzzerName].push(reportPath);
    }
  });

  const reportCompleteBinaries = Object.keys(reportsByBinaryAndFuzzer);

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

    const incompleteBinaries: string[] = [];
    Object.entries(data.selectedReports).forEach(([binary, fuzzerReports]) => {
      const missingFuzzers = selectedFuzzers.filter(
        (fuzzer) => !fuzzerReports[fuzzer],
      );
      if (missingFuzzers.length > 0) {
        incompleteBinaries.push(
          `${binary} (missing: ${missingFuzzers.join(", ")})`,
        );
      }
    });

    if (incompleteBinaries.length > 0) {
      form.setError("selectedReports", {
        type: "manual",
        message: `Please select a report for all fuzzers in: ${incompleteBinaries.join("; ")}`,
      });
      return;
    }

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
      });
      const response = await fetch(`${API_URL}/api/table/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          benchmark,
          fuzzers: selectedFuzzers,
          report_paths: selectedReportPaths,
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

  useEffect(() => {
    const fetchValidFuzzers = async () => {
      try {
        const response = await fetch(
          `${API_URL}/api/check_fuzzers?benchmark=${benchmark}`,
        );
        const data = await response.json();
        if (data.valid_fuzzers) {
          setValidFuzzers(data.valid_fuzzers);
        }
      } catch (error) {
        console.error("Failed to fetch valid fuzzers:", error);
        setValidFuzzers(fuzzers);
      }
    };

    if (benchmark) {
      fetchValidFuzzers();
    }
  }, [benchmark, fuzzers]);

  const fetchReportsFor = async (selectedFuzzers: string[]) => {
    if (!selectedFuzzers || selectedFuzzers.length === 0) {
      setReportPaths([]);
      setReportDurations({});
      setAvailableBinaries([]);
      setUnavailableReasons({});
      return;
    }

    setLoadingReports(true);
    try {
      const [reportsResponse, binariesResponse] = await Promise.all([
        fetch(`${API_URL}/api/get_reports`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            benchmark: benchmark,
            fuzzers: selectedFuzzers,
          }),
        }),
        fetch(`${API_URL}/api/check_binaries`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            benchmark: benchmark,
            fuzzers: selectedFuzzers,
          }),
        }),
      ]);

      const reportsData = await reportsResponse.json();
      const binariesData = await binariesResponse.json();

      const validReports = reportsData.valid_reports || [];
      const durations = reportsData.report_durations || {};
      const validBinaries = binariesData.valid_binaries || [];

      setReportPaths(validReports);
      setReportDurations(durations);
      setAvailableBinaries(validBinaries);

      const binariesWithCompleteReports = new Set<string>();
      validReports.forEach((reportPath: string) => {
        const extracted = extractBinaryAndFuzzer(reportPath);
        if (extracted) {
          binariesWithCompleteReports.add(extracted.binaryName);
        }
      });

      const unavailableBinaries = validBinaries.filter(
        (binary: string) => !binariesWithCompleteReports.has(binary),
      );

      if (unavailableBinaries.length > 0) {
        const perFuzzerReports = await Promise.all(
          selectedFuzzers.map(async (fuzzer) => {
            try {
              const response = await fetch(`${API_URL}/api/get_reports`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  benchmark,
                  fuzzers: [fuzzer],
                }),
              });
              const data = await response.json();
              return { fuzzer, reports: data.valid_reports || [] };
            } catch {
              return { fuzzer, reports: [] };
            }
          }),
        );

        const fuzzerBinarySets: Record<string, Set<string>> = {};
        perFuzzerReports.forEach(({ fuzzer, reports }) => {
          const binariesForFuzzer = new Set<string>();
          reports.forEach((reportPath: string) => {
            const extracted = extractBinaryAndFuzzer(reportPath);
            if (extracted) {
              binariesForFuzzer.add(extracted.binaryName);
            }
          });
          fuzzerBinarySets[fuzzer] = binariesForFuzzer;
        });

        const reasons: Record<string, string> = {};
        unavailableBinaries.forEach((binary: string) => {
          const missingFuzzers = selectedFuzzers.filter(
            (fuzzer) => !fuzzerBinarySets[fuzzer]?.has(binary),
          );
          reasons[binary] =
            missingFuzzers.length > 0
              ? `No result for ${binary} and ${missingFuzzers.join(", ")}`
              : `No result for ${binary} and selected fuzzers`;
        });
        setUnavailableReasons(reasons);
      } else {
        setUnavailableReasons({});
      }
    } catch (error) {
      console.error("Failed to fetch reports:", error);
      setReportPaths([]);
      setReportDurations({});
      setAvailableBinaries([]);
      setUnavailableReasons({});
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
          Object.entries(currentReports)
            .map(([binary, fuzzerReports]) => [
              binary,
              Object.fromEntries(
                Object.entries(fuzzerReports).filter(([fuzzer]) =>
                  selectedFuzzers.includes(fuzzer),
                ),
              ),
            ])
            .filter(
              ([, fuzzerReports]) => Object.keys(fuzzerReports).length > 0,
            ),
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
    const parts = reportPath.split("/");
    let outputName = reportPath;
    const fuzzingOutIndex = parts.findIndex((p) => p === "fuzzing_out");
    if (fuzzingOutIndex !== -1 && fuzzingOutIndex + 1 < parts.length) {
      outputName = parts[fuzzingOutIndex + 1];
    }

    const durationSeconds = reportDurations[reportPath];
    if (durationSeconds === null || durationSeconds === undefined || Number.isNaN(Number(durationSeconds))) {
      return outputName;
    }

    const totalSeconds = Math.max(0, Number(durationSeconds));
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = Math.floor(totalSeconds % 60);

    let durationLabel = '';
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
    const parts = reportPath.split("/");
    const fuzzingOutIndex = parts.findIndex((p) => p === "fuzzing_out");
    if (fuzzingOutIndex !== -1 && fuzzingOutIndex + 1 < parts.length) {
      const timestamp = parts[fuzzingOutIndex + 1];
      const match = timestamp.match(
        /(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})/,
      );
      if (match) {
        const [, year, month, day, hour, minute, second] = match;
        return new Date(
          `${year}-${month}-${day}T${hour}:${minute}:${second}`,
        ).getTime();
      }
    }
    return 0;
  };

  const getOutputFolderName = (reportPath: string): string => {
    const parts = reportPath.split("/");
    const fuzzingOutIndex = parts.findIndex((p) => p === "fuzzing_out");
    if (fuzzingOutIndex !== -1 && fuzzingOutIndex + 1 < parts.length) {
      return parts[fuzzingOutIndex + 1];
    }
    return reportPath;
  };

  const selectMatchingFolderReports = (binary: string) => {
    const currentValue = form.getValues("selectedReports") || {};
    const newValue = { ...currentValue };

    if (!newValue[binary]) {
      newValue[binary] = {};
    }

    const selectedFuzzerList = selectedFuzzers || [];
    if (selectedFuzzerList.length === 0) {
      return;
    }

    const outputNameSetsByFuzzer: Record<string, Set<string>> = {};
    selectedFuzzerList.forEach((fuzzer) => {
      const reportsForFuzzer = reportsByBinaryAndFuzzer[binary]?.[fuzzer] || [];
      outputNameSetsByFuzzer[fuzzer] = new Set(
        reportsForFuzzer.map((path) => getOutputFolderName(path)),
      );
    });

    const [firstFuzzer, ...otherFuzzers] = selectedFuzzerList;
    const firstSet = outputNameSetsByFuzzer[firstFuzzer] || new Set<string>();
    const commonOutputNames = Array.from(firstSet).filter((outputName) =>
      otherFuzzers.every((fuzzer) =>
        outputNameSetsByFuzzer[fuzzer]?.has(outputName),
      ),
    );

    if (commonOutputNames.length === 0) {
      form.setError("selectedReports", {
        type: "manual",
        message: `No common output folder name found for ${binary} across selected fuzzers. Select reports manually in details.`,
      });
      return;
    }

    const chosenOutputName = commonOutputNames.reduce((latest, current) => {
      const latestTime = getReportTimestamp(latest);
      const currentTime = getReportTimestamp(current);
      return currentTime > latestTime ? current : latest;
    });

    selectedFuzzerList.forEach((fuzzer) => {
      const reportsForFuzzer = reportsByBinaryAndFuzzer[binary]?.[fuzzer] || [];
      if (reportsForFuzzer.length > 0) {
        const matchingReports = reportsForFuzzer.filter(
          (path) => getOutputFolderName(path) === chosenOutputName,
        );

        if (matchingReports.length > 0) {
          const selectedReportPath = matchingReports.reduce((latest, current) => {
            const latestTime = getReportTimestamp(latest);
            const currentTime = getReportTimestamp(current);
            return currentTime > latestTime ? current : latest;
          });
          newValue[binary][fuzzer] = selectedReportPath;
        }
      }
    });

    form.clearErrors("selectedReports");
    form.setValue("selectedReports", newValue);
  };

  return (
    <Sheet
      open={open}
      onOpenChange={(v) => {
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
                  <FormLabel className="flex items-center gap-2">
                    Fuzzers
                    <Badge variant="secondary" className="text-xs">
                      {field.value?.length || 0} selected
                    </Badge>
                  </FormLabel>
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
                          const isValid =
                            validFuzzers.length === 0 ||
                            validFuzzers.includes(fuzzer);
                          return (
                            <div
                              key={fuzzer}
                              className={`flex items-center space-x-2 p-2 rounded-md transition-colors ${
                                isSelected
                                  ? "bg-primary/10 border border-primary"
                                  : "border border-transparent"
                              } ${!isValid ? "opacity-50" : ""}`}
                            >
                              <Checkbox
                                checked={isSelected}
                                disabled={!isValid}
                                onCheckedChange={(checked) => {
                                  if (!isValid) return;
                                  const currentValue = field.value || [];
                                  const newValue = checked
                                    ? [...currentValue, fuzzer]
                                    : currentValue.filter((v) => v !== fuzzer);
                                  field.onChange(newValue);
                                }}
                              />
                              <label
                                className={`flex-1 text-sm font-medium ${isValid ? "cursor-pointer" : "cursor-not-allowed"}`}
                                onClick={() => {
                                  if (!isValid) return;
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
                const filteredBinaries = reportCompleteBinaries.filter((binary) =>
                  binary.toLowerCase().includes(binarySearch.toLowerCase()),
                );
                const unavailableBinaries = availableBinaries
                  .filter((binary) => !reportCompleteBinaries.includes(binary))
                  .filter((binary) =>
                    binary.toLowerCase().includes(binarySearch.toLowerCase()),
                  )
                  .sort((a, b) => a.localeCompare(b));

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
                      Click a binary to expand. Select one report per fuzzer for
                      each binary. Use "Match" to auto-pick the
                      same output folder name across selected fuzzers.
                    </FormDescription>
                    {(reportCompleteBinaries.length > 0 ||
                      availableBinaries.length > 0) && (
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
                      ) : filteredBinaries.length > 0 ||
                        unavailableBinaries.length > 0 ? (
                        <div className="space-y-1">
                          {filteredBinaries.map((binary) => {
                            const isExpanded = expandedBinaries.has(binary);
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
                                  <TooltipProvider>
                                    <Tooltip>
                                      <TooltipTrigger asChild>
                                        <Button
                                          type="button"
                                          size="sm"
                                          variant="ghost"
                                          className="text-xs h-7 px-2 shrink-0 whitespace-nowrap"
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            selectMatchingFolderReports(binary);
                                          }}
                                        >
                                          Match
                                        </Button>
                                      </TooltipTrigger>
                                      <TooltipContent>
                                        <p>Select Matching Output Directory</p>
                                      </TooltipContent>
                                    </Tooltip>
                                  </TooltipProvider>
                                </div>

                                {isExpanded &&
                                  selectedFuzzers &&
                                  selectedFuzzers.length > 0 && (
                                    <div className="ml-6 space-y-2 py-1">
                                      {selectedFuzzers.map((fuzzer) => {
                                        const reportsForFuzzer =
                                          reportsByBinaryAndFuzzer[binary]?.[
                                            fuzzer
                                          ] || [];
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

                          {unavailableBinaries.length > 0 && (
                            <div className="pt-2 mt-2 border-t space-y-1">
                              {unavailableBinaries.map((binary) => (
                                <TooltipProvider key={binary}>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <div className="flex items-center space-x-2 p-2 rounded-md border border-dashed opacity-50 cursor-not-allowed">
                                        <span className="flex-1 text-sm font-medium">
                                          {binary}
                                        </span>
                                        <Badge
                                          variant="outline"
                                          className="text-xs"
                                        >
                                          Unavailable
                                        </Badge>
                                      </div>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                      <p>
                                        {unavailableReasons[binary] ||
                                          `No result for ${binary} and selected fuzzers`}
                                      </p>
                                    </TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (reportCompleteBinaries.length > 0 ||
                          availableBinaries.length > 0) &&
                        filteredBinaries.length === 0 ? (
                        <p className="text-sm text-muted-foreground">
                          No binaries match your search
                        </p>
                      ) : (
                        <p className="text-sm text-muted-foreground">
                          {form.watch("fuzzer")?.length > 0
                            ? "No frb reports available for selected benchmark and fuzzers"
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
