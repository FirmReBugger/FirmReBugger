import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { SlidersHorizontal } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { UpSetPlot } from "./components/upset-plot";
import { BugTable } from "./components/bug-table";

type BinaryGroup = {
  binary: string;
  bugs: Array<{ bugId: string }>;
};

const hasReportData = (data: BinaryGroup[] | null): boolean => {
  if (!Array.isArray(data) || data.length === 0) return false;
  return data.some((group) => Array.isArray(group.bugs) && group.bugs.length > 0);
};

export function Report() {
  const [drawerSelectedBenchmark, setDrawerSelectedBenchmark] = useState<string | null>(null);
  const [selectedTab, setSelectedTab] = useState(
    () => localStorage.getItem("report-selected-tab") || "firmbench"
  );
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [firmBenchData, setFirmBenchData] = useState<BinaryGroup[] | null>(null);
  const [firmBenchXData, setFirmBenchXData] = useState<BinaryGroup[] | null>(null);
  const [firmBenchDMAData, setFirmBenchDMAData] = useState<BinaryGroup[] | null>(null);
  const [firmBenchReportPaths, setFirmBenchReportPaths] = useState<string[]>([]);
  const [firmBenchXReportPaths, setFirmBenchXReportPaths] = useState<string[]>([]);
  const [firmBenchDMAReportPaths, setFirmBenchDMAReportPaths] = useState<string[]>([]);
  const [showEmptyHint, setShowEmptyHint] = useState(false);

  const tabToBenchmark = (tabValue: string) => {
    switch (tabValue) {
      case "firmbench":
        return "FirmBench";
      case "firmbenchx":
        return "FirmBenchX";
      case "firmbenchdma":
        return "FirmBenchDMA";
      default:
        return tabValue;
    }
  };

  useEffect(() => {
    if (drawerOpen) {
      setDrawerSelectedBenchmark(tabToBenchmark(selectedTab));
    }
  }, [drawerOpen, selectedTab]);

  useEffect(() => {
    const currentDataByTab: Record<string, BinaryGroup[] | null> = {
      firmbench: firmBenchData,
      firmbenchx: firmBenchXData,
      firmbenchdma: firmBenchDMAData,
    };
    const currentData = currentDataByTab[selectedTab] ?? null;

    if (hasReportData(currentData)) {
      setShowEmptyHint(false);
      return;
    }

    setShowEmptyHint(false);
    const timeout = setTimeout(() => setShowEmptyHint(true), 450);
    return () => clearTimeout(timeout);
  }, [selectedTab, firmBenchData, firmBenchXData, firmBenchDMAData]);

  const renderTabContent = (
    benchmark: "FirmBench" | "FirmBenchX" | "FirmBenchDMA",
    data: BinaryGroup[] | null,
    reportPaths: string[],
    setData: (data: BinaryGroup[] | null) => void,
    setPaths: (paths: string[]) => void,
  ) => {
    const empty = !hasReportData(data);
    const isActiveTab = tabToBenchmark(selectedTab) === benchmark;
    const showOverlay = empty && isActiveTab && showEmptyHint;

    return (
      <div className="relative">
        <div
          className={
            empty
              ? "pointer-events-none opacity-45 grayscale transition-all duration-300 space-y-4"
              : "transition-all duration-300 space-y-4"
          }
        >
          <BugTable
            benchmark={benchmark}
            openDrawer={drawerOpen === true && drawerSelectedBenchmark === benchmark}
            onOpenChange={(v) => setDrawerOpen(v)}
            onDataUpdate={setData}
            onReportPathsUpdate={setPaths}
          />
          <UpSetPlot benchmark={benchmark} tableData={data} reportPaths={reportPaths} />
        </div>

        {showOverlay ? (
          <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center opacity-100 transition-opacity duration-300">
            <div className="pointer-events-auto max-w-md rounded-xl border bg-background/95 p-5 text-center shadow-lg backdrop-blur">
              <p className="text-base font-semibold">No report data yet</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Queue and run jobs first, then come back to view Bug Table and UpSet Plot results.
              </p>
              <div className="mt-4">
                <Link
                  to="/manager"
                  className="inline-flex items-center rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                >
                  Go to Job manager
                </Link>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    );
  };

  return (
    <section>
      <div className="mb-2 flex items-center justify-between space-y-2">
        <h1 className="text-2xl font-bold tracking-tight">FirmReBugger Report</h1>
      </div>

      <Tabs
        orientation="horizontal"
        className="space-y-4"
        value={selectedTab}
        onValueChange={(v) => {
          setSelectedTab(v);
          localStorage.setItem("report-selected-tab", v);
        }}
      >
        <div className="w-full overflow-x-auto pb-2 flex items-center justify-between">
          <TabsList>
            <TabsTrigger value="firmbench">FirmBench</TabsTrigger>
            <TabsTrigger value="firmbenchx">FirmBenchX</TabsTrigger>
            <TabsTrigger value="firmbenchdma">FirmBenchDMA</TabsTrigger>
          </TabsList>
          <div>
            <button
              className="inline-flex items-center gap-2 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-md hover:bg-primary/80 transition-colors"
              onClick={() => {
                const bench = tabToBenchmark(selectedTab);
                setDrawerSelectedBenchmark(bench);
                setDrawerOpen(true);
              }}
            >
              <SlidersHorizontal className="h-4 w-4" />
              Configure
            </button>
          </div>
        </div>

        <TabsContent value="firmbench" className="space-y-4">
          {renderTabContent(
            "FirmBench",
            firmBenchData,
            firmBenchReportPaths,
            setFirmBenchData,
            setFirmBenchReportPaths,
          )}
        </TabsContent>

        <TabsContent value="firmbenchx" className="space-y-4">
          {renderTabContent(
            "FirmBenchX",
            firmBenchXData,
            firmBenchXReportPaths,
            setFirmBenchXData,
            setFirmBenchXReportPaths,
          )}
        </TabsContent>

        <TabsContent value="firmbenchdma" className="space-y-4">
          {renderTabContent(
            "FirmBenchDMA",
            firmBenchDMAData,
            firmBenchDMAReportPaths,
            setFirmBenchDMAData,
            setFirmBenchDMAReportPaths,
          )}
        </TabsContent>
      </Tabs>
    </section>
  );
}
