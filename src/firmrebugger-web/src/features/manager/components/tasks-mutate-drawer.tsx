import { z } from "zod";
import { useState, useEffect } from "react";
import { useApiUrl } from "@/context/api-url-context";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Check } from "lucide-react";
import { showSubmittedData } from "@/lib/show-submitted-data";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormDescription,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { type Task } from "../data/schema";
import { useTasks } from "./tasks-provider";

function parseTimeToSeconds(timeStr: string): number {
  const str = timeStr.trim();

  if (/^\d+$/.test(str)) {
    return parseInt(str);
  }

  const match = str.match(/^(\d+(?:\.\d+)?)\s*([dhms])$/i);
  if (!match) {
    return 0;
  }

  const value = parseFloat(match[1]);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case "d":
      return Math.round(value * 24 * 60 * 60);
    case "h":
      return Math.round(value * 60 * 60);
    case "m":
      return Math.round(value * 60);
    case "s":
      return Math.round(value);
    default:
      return 0;
  }
}

export function formatTime(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  } else if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  } else if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  } else {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  }
}

type TaskMutateDrawerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentRow?: Task;
};

const formSchema = z.object({
  fuzzer: z.array(z.string()).min(1, "At least one fuzzer is required."),
  binary: z.array(z.string()).min(1, "At least one binary is required."),
  runs: z.number().min(1, "Runs must be at least 1."),
  time: z.number().min(1, "Time must be at least 1 second."),
  output_dir: z.string().min(1, "Output directory is required."),
});
type TaskForm = z.infer<typeof formSchema>;

type BinarySupport = {
  binary: string;
  is_supported: boolean;
  missing_fuzzers: string[];
};

export function TasksMutateDrawer({
  open,
  onOpenChange,
  currentRow,
}: TaskMutateDrawerProps) {
  const isUpdate = !!currentRow;
  const { setTasks } = useTasks();
  const [timeInput, setTimeInput] = useState("");
  const [fuzzers, setFuzzers] = useState<string[]>([]);
  const [loadingFuzzers, setLoadingFuzzers] = useState(false);
  const [selectedBenchmark, setSelectedBenchmark] =
    useState<string>("FirmBench");
  const [validFuzzers, setValidFuzzers] = useState<string[]>([]);
  const [binaries, setBinaries] = useState<string[]>([]);
  const [binarySupport, setBinarySupport] = useState<BinarySupport[]>([]);
  const [loadingBinaries, setLoadingBinaries] = useState(false);
  const [binarySearch, setBinarySearch] = useState("");
  const [maxCores, setMaxCores] = useState<number>(32);
  const API_URL = useApiUrl();

  useEffect(() => {
    const fetchFuzzers = async () => {
      setLoadingFuzzers(true);
      try {
        const response = await fetch(`${API_URL}/api/fuzzers/list`);
        const data = await response.json();
        console.log("Fetched fuzzer data:", data);

        if (data.items) {
          const fuzzerNames = data.items
            .filter((item: any) => item.type === "directory")
            .map((item: any) => item.name);
          console.log("Fuzzer names:", fuzzerNames);
          setFuzzers(fuzzerNames);
        }
      } catch (error) {
        console.error("Failed to fetch fuzzers:", error);
      } finally {
        setLoadingFuzzers(false);
      }
    };

    fetchFuzzers();
  }, [API_URL]);

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
  }, [API_URL]);

  const form = useForm<TaskForm>({
    resolver: zodResolver(formSchema),
    defaultValues: currentRow
      ? {
          fuzzer: [currentRow.fuzzer],
          binary: [currentRow.binary],
          runs: currentRow.runs,
          time: currentRow.time,
          output_dir: currentRow.output_dir,
        }
      : {
          fuzzer: [],
          binary: [],
          runs: 1,
          time: 0,
          output_dir: "",
        },
  });

  const onSubmit = async (data: TaskForm) => {
    const maxAllowed = Math.max(1, maxCores - 2);
    if (data.runs > maxAllowed) {
      form.setError("runs", {
        type: "manual",
        message: `Runs cannot exceed ${maxAllowed} (max cores - 2)`,
      });
      return;
    }

    if (isUpdate && currentRow) {
      const firstFuzzer = Array.isArray(data.fuzzer)
        ? data.fuzzer[0]
        : data.fuzzer;
      const firstBinary = Array.isArray(data.binary)
        ? data.binary[0]
        : data.binary;
      setTasks((prevTasks) =>
        prevTasks.map((task) =>
          task.id === currentRow.id
            ? { ...task, ...data, fuzzer: firstFuzzer, binary: firstBinary }
            : task,
        ),
      );
    } else {
      const selectedFuzzers = Array.isArray(data.fuzzer)
        ? data.fuzzer
        : [data.fuzzer];
      const selectedBinaries = Array.isArray(data.binary)
        ? data.binary
        : [data.binary];

      try {
        const response = await fetch(`${API_URL}/api/check_output_name`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            benchmark: selectedBenchmark,
            binary_name: selectedBinaries[0],
            fuzzers_selected: selectedFuzzers,
            output_name: data.output_dir,
          }),
        });

        const result = await response.json();

        if (!result.is_valid) {
          form.setError("output_dir", {
            type: "manual",
            message:
              "Output directory name already exists for this configuration",
          });
          return; // Stop submission
        }
      } catch (error) {
        console.error("Error validating output name:", error);
        form.setError("output_dir", {
          type: "manual",
          message: "Failed to validate output directory name",
        });
        return;
      }

      const newTasks: Task[] = [];
      const jobsData: any[] = [];
      let taskIndex = 0;

      for (const fuzzer of selectedFuzzers) {
        for (const binary of selectedBinaries) {
          const timestamp = Date.now();
          newTasks.push({
            id: `TASK-${timestamp}-${taskIndex}`,
            mode: "Fuzzing",
            benchmark: selectedBenchmark,
            fuzzer: fuzzer,
            binary: binary,
            runs: data.runs,
            time: data.time,
            output_dir: data.output_dir,
            status: "queued" as const,
            progress: 0,
            elapsedTime: 0,
            createdAt: new Date(),
            startTime: new Date(),
            completedAt: undefined,
            autoQueueTriaging: true,
            triaged: false,
          });

          jobsData.push({
            job_id: `JOB-${timestamp}-${taskIndex}`,
            fuzzer: fuzzer,
            benchmark: selectedBenchmark,
            duration: data.time,
            binary: binary,
            runs: data.runs,
            mode: "Fuzzing",
            output_dir: data.output_dir,
          });

          taskIndex++;
        }
      }

      try {
        const response = await fetch(`${API_URL}/api/jobs/add`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            jobs: jobsData,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || "Failed to create job");
        }

        const result = await response.json();
        console.log("Job created successfully:", result);
      } catch (error) {
        console.error("Error creating job:", error);
        return;
      }

      setTasks((prevTasks) => [...prevTasks, ...newTasks]);
    }
    onOpenChange(false);
    form.reset();

    const selectedFuzzers = Array.isArray(data.fuzzer)
      ? data.fuzzer
      : [data.fuzzer];
    const selectedBinaries = Array.isArray(data.binary)
      ? data.binary
      : [data.binary];
    const totalTasks = selectedFuzzers.length * selectedBinaries.length;
    if (!isUpdate && totalTasks > 1) {
      showSubmittedData(
        { ...data, count: totalTasks },
        `Created ${totalTasks} tasks (${selectedFuzzers.length} fuzzer(s) × ${selectedBinaries.length} binary/binaries):`,
      );
    } else {
      showSubmittedData(data);
    }
  };

  useEffect(() => {
    const fetchValidFuzzers = async () => {
      console.log("Fetching valid fuzzers for benchmark:", selectedBenchmark);
      try {
        const url = `${API_URL}/api/check_fuzzers?benchmark=${selectedBenchmark}`;
        console.log("Calling API:", url);
        const response = await fetch(url);
        const data = await response.json();
        console.log("API response for check_fuzzers:", data);

        if (data.valid_fuzzers) {
          console.log(
            "Valid fuzzers for",
            selectedBenchmark,
            ":",
            data.valid_fuzzers,
          );
          setValidFuzzers(data.valid_fuzzers);
        } else {
          console.log("No valid_fuzzers in response, setting empty array");
          setValidFuzzers([]);
        }
      } catch (error) {
        console.error("Failed to fetch valid fuzzers:", error);
        setValidFuzzers([]);
      }
    };

    console.log(
      "useEffect triggered - selectedBenchmark:",
      selectedBenchmark,
      "fuzzers.length:",
      fuzzers.length,
    );
    if (selectedBenchmark && fuzzers.length > 0) {
      fetchValidFuzzers();
    } else {
      console.log("Skipping fetch - condition not met");
    }
  }, [selectedBenchmark, fuzzers.length, API_URL]);

  useEffect(() => {
    const subscription = form.watch((value, { name }) => {
      if (name === "fuzzer") {
        const fetchBinaries = async () => {
          const selectedFuzzers = value.fuzzer || [];
          console.log("Fuzzer changed, selected:", selectedFuzzers);

          if (selectedFuzzers.length === 0) {
            setBinaries([]);
            setBinarySupport([]);
            return;
          }

          setLoadingBinaries(true);
          try {
            console.log("Fetching binaries for:", {
              benchmark: selectedBenchmark,
              fuzzers: selectedFuzzers,
            });
            const response = await fetch(`${API_URL}/api/check_binaries`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                benchmark: selectedBenchmark,
                fuzzers: selectedFuzzers,
              }),
            });
            const data = await response.json();
            console.log("Received binaries:", data);
            const supportData: BinarySupport[] = Array.isArray(
              data.binary_support,
            )
              ? data.binary_support
              : [];

            if (supportData.length > 0) {
              setBinarySupport(supportData);
              setBinaries(
                supportData.filter((b) => b.is_supported).map((b) => b.binary),
              );

              const supportedSet = new Set(
                supportData.filter((b) => b.is_supported).map((b) => b.binary),
              );
              const currentlySelected = form.getValues("binary") || [];
              const stillValid = currentlySelected.filter((binary) =>
                supportedSet.has(binary),
              );
              if (stillValid.length !== currentlySelected.length) {
                form.setValue("binary", stillValid);
              }
            } else if (data.valid_binaries) {
              setBinaries(data.valid_binaries);
              setBinarySupport(
                (data.valid_binaries as string[]).map((binary) => ({
                  binary,
                  is_supported: true,
                  missing_fuzzers: [],
                })),
              );
            }
          } catch (error) {
            console.error("Failed to fetch binaries:", error);
            setBinaries([]);
            setBinarySupport([]);
          } finally {
            setLoadingBinaries(false);
          }
        };

        fetchBinaries();
      }
    });

    return () => subscription.unsubscribe();
  }, [selectedBenchmark, form, API_URL]);

  return (
    <Sheet
      open={open}
      onOpenChange={(v) => {
        onOpenChange(v);
        if (!v) {
          form.reset();
          setTimeInput("");
          setSelectedBenchmark("FirmBench");
          setBinarySearch("");
        }
      }}
    >
      <SheetContent className="flex flex-col">
        <SheetHeader className="text-start">
          <SheetTitle>{isUpdate ? "Update" : "Create"} Job</SheetTitle>
          <SheetDescription>
            {isUpdate
              ? "Update the job details."
              : `Add a new fuzzing job for ${selectedBenchmark}.`}{" "}
            Click Submit when you are done.
          </SheetDescription>
        </SheetHeader>

        {/* Benchmark Tabs */}
        {!isUpdate && (
          <Tabs
            value={selectedBenchmark}
            onValueChange={(value) => {
              setSelectedBenchmark(value);
              form.setValue("fuzzer", []);
              form.setValue("binary", []);
              setBinaries([]);
              setBinarySupport([]);
            }}
            className="w-full px-4"
          >
            <TabsList className="w-full">
              <TabsTrigger value="FirmBench" className="flex-1">
                FirmBench
              </TabsTrigger>
              <TabsTrigger value="FirmBenchX" className="flex-1">
                FirmBenchX
              </TabsTrigger>
              <TabsTrigger value="FirmBenchDMA" className="flex-1">
                FirmBenchDMA
              </TabsTrigger>
            </TabsList>
          </Tabs>
        )}

        <Form {...form}>
          <form
            id="tasks-form"
            onSubmit={form.handleSubmit(onSubmit)}
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
              name="binary"
              render={({ field }) => {
                const binaryOptions =
                  binarySupport.length > 0
                    ? binarySupport
                    : binaries.map((binary) => ({
                        binary,
                        is_supported: true,
                        missing_fuzzers: [] as string[],
                      }));

                const filteredSupported = binaryOptions.filter(
                  (item) =>
                    item.is_supported &&
                    item.binary
                      .toLowerCase()
                      .includes(binarySearch.toLowerCase()),
                );
                const filteredUnsupported = binaryOptions.filter(
                  (item) =>
                    !item.is_supported &&
                    item.binary
                      .toLowerCase()
                      .includes(binarySearch.toLowerCase()),
                );
                const filteredBinaries = [
                  ...filteredSupported,
                  ...filteredUnsupported,
                ];

                return (
                  <FormItem>
                    <FormLabel className="flex items-center gap-2">
                      Binaries
                      <Badge variant="secondary" className="text-xs">
                        {field.value?.length || 0} selected
                      </Badge>
                    </FormLabel>
                    <FormDescription className="text-xs">
                      Select one or more binaries (filtered by benchmark and
                      fuzzers)
                    </FormDescription>
                    {binaryOptions.length > 0 && (
                      <Input
                        type="text"
                        placeholder="Search binaries..."
                        value={binarySearch}
                        onChange={(e) => setBinarySearch(e.target.value)}
                        className="mb-2"
                      />
                    )}
                    <div className="border rounded-md p-3 max-h-60 overflow-y-auto">
                      {loadingBinaries ? (
                        <p className="text-sm text-muted-foreground">
                          Loading binaries...
                        </p>
                      ) : filteredBinaries.length > 0 ? (
                        <div className="space-y-2">
                          {filteredBinaries.map((binaryItem) => {
                            const binary = binaryItem.binary;
                            const isSelected = field.value?.includes(binary);
                            const isSupported = binaryItem.is_supported;
                            const tooltipText =
                              binaryItem.missing_fuzzers.length > 0
                                ? `Not supported by: ${binaryItem.missing_fuzzers.join(", ")}`
                                : "Not supported by selected fuzzers";
                            return (
                              <div
                                key={binary}
                                className={`flex items-center space-x-2 p-1.5 rounded ${isSupported ? "" : "opacity-50"}`}
                              >
                                <Checkbox
                                  id={`binary-${binary}`}
                                  checked={isSelected}
                                  disabled={!isSupported}
                                  onCheckedChange={(checked) => {
                                    if (!isSupported) return;
                                    const currentValue = field.value || [];
                                    if (checked) {
                                      field.onChange([...currentValue, binary]);
                                    } else {
                                      field.onChange(
                                        currentValue.filter(
                                          (f: string) => f !== binary,
                                        ),
                                      );
                                    }
                                  }}
                                />
                                {isSupported ? (
                                  <label
                                    htmlFor={`binary-${binary}`}
                                    className="text-sm font-normal leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer flex-1"
                                  >
                                    {binary}
                                  </label>
                                ) : (
                                  <TooltipProvider>
                                    <Tooltip>
                                      <TooltipTrigger asChild>
                                        <label
                                          htmlFor={`binary-${binary}`}
                                          className="text-sm font-normal leading-none cursor-not-allowed flex-1"
                                        >
                                          {binary}
                                        </label>
                                      </TooltipTrigger>
                                      <TooltipContent>
                                        <p>{tooltipText}</p>
                                      </TooltipContent>
                                    </Tooltip>
                                  </TooltipProvider>
                                )}
                                {isSelected && (
                                  <Check className="h-4 w-4 text-primary" />
                                )}
                              </div>
                            );
                          })}
                        </div>
                      ) : binaryOptions.length > 0 &&
                        filteredBinaries.length === 0 ? (
                        <p className="text-sm text-muted-foreground">
                          No binaries match your search
                        </p>
                      ) : (
                        <p className="text-sm text-muted-foreground">
                          {form.watch("fuzzer")?.length > 0
                            ? "No binaries available for selected benchmark and fuzzers"
                            : "Please select at least one fuzzer first"}
                        </p>
                      )}
                    </div>
                    <FormMessage />
                  </FormItem>
                );
              }}
            />
            <FormField
              control={form.control}
              name="runs"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Runs</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      type="number"
                      min="1"
                      max={Math.max(1, maxCores - 2)}
                      placeholder="Number of runs (minimum 1)"
                      onChange={(e) => {
                        const value = e.target.value;
                        if (value === "") {
                          field.onChange("");
                        } else {
                          const numValue = parseInt(value);
                          const maxAllowed = Math.max(1, maxCores - 2);
                          if (!isNaN(numValue)) {
                            field.onChange(
                              Math.min(Math.max(1, numValue), maxAllowed),
                            );
                          }
                        }
                      }}
                      onBlur={(e) => {
                        const value = parseInt(e.target.value);
                        if (isNaN(value) || value < 1) {
                          field.onChange(1);
                        }
                      }}
                    />
                  </FormControl>
                  <FormDescription className="text-xs">
                    Must be at least 1, max {Math.max(1, maxCores - 2)} (total
                    cores - 2)
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="time"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Time</FormLabel>
                  <FormControl>
                    <Input
                      value={
                        timeInput ||
                        (field.value > 0 ? formatTime(field.value) : "")
                      }
                      onChange={(e) => {
                        const input = e.target.value;
                        setTimeInput(input);
                        const seconds = parseTimeToSeconds(input);
                        if (seconds > 0) {
                          field.onChange(seconds);
                        } else if (input === "") {
                          field.onChange(0);
                        }
                      }}
                      onBlur={() => {
                        if (field.value > 0) {
                          setTimeInput("");
                        }
                      }}
                      placeholder="e.g., 24h, 30m, 2d, or 300"
                    />
                  </FormControl>
                  <FormDescription className="text-xs">
                    Use d (days), h (hours), m (minutes), s (seconds), or just a
                    number
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="output_dir"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Output Directory</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="e.g., my_test_output"
                      onBlur={async () => {
                        const selectedFuzzers = form.watch("fuzzer");
                        const selectedBinaries = form.watch("binary");

                        if (
                          field.value &&
                          selectedFuzzers?.length > 0 &&
                          selectedBinaries?.length > 0
                        ) {
                          try {
                            const response = await fetch(
                              `${API_URL}/api/check_output_name`,
                              {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({
                                  benchmark: selectedBenchmark,
                                  binary_name: selectedBinaries[0],
                                  fuzzers_selected: selectedFuzzers,
                                  output_name: field.value,
                                }),
                              },
                            );

                            const result = await response.json();

                            if (!result.is_valid) {
                              form.setError("output_dir", {
                                type: "manual",
                                message:
                                  "Output directory name already exists for this configuration",
                              });
                            } else {
                              form.clearErrors("output_dir");
                            }
                          } catch (error) {
                            console.error(
                              "Error validating output name:",
                              error,
                            );
                          }
                        }
                      }}
                    />
                  </FormControl>
                  <FormDescription className="text-xs">
                    Name for the output directory where fuzzing results will be
                    saved
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </form>
        </Form>
        <SheetFooter className="gap-2">
          <SheetClose asChild>
            <Button variant="outline">Cancel</Button>
          </SheetClose>
          <Button type="submit" form="tasks-form">
            Submit
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
