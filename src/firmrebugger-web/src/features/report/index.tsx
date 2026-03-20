import { useState, useEffect } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Header } from "@/components/layout/header";
import { Main } from "@/components/layout/main";
import { UpSetPlot } from "./components/upset-plot";
import { BugTable } from "./components/bug-table";

export function Report() {
  const [drawerSelectedBenchmark, setDrawerSelectedBenchmark] = useState<
    string | null
  >(null);
  const [selectedTab, setSelectedTab] = useState(() => {
    return localStorage.getItem("report-selected-tab") || "firmbench";
  });
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [firmBenchData, setFirmBenchData] = useState<any>(null);
  const [firmBenchXData, setFirmBenchXData] = useState<any>(null);
  const [firmBenchDMAData, setFirmBenchDMAData] = useState<any>(null);

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
  }, [selectedTab, drawerOpen]);

  return (
    <>
      <Header />
      <Main>
        <div className="mb-2 flex items-center justify-between space-y-2">
          <h1 className="text-2xl font-bold tracking-tight">
            FirmReBugger Report
          </h1>
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
                className="px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-md hover:bg-primary/80 transition-colors"
                onClick={() => {
                  const bench = tabToBenchmark(selectedTab);
                  setDrawerSelectedBenchmark(bench);
                  setDrawerOpen(true);
                }}
              >
                Configure
              </button>
            </div>
          </div>

          <TabsContent value="firmbench" className="space-y-4">
            <BugTable
              benchmark="FirmBench"
              openDrawer={
                drawerOpen === true && drawerSelectedBenchmark === "FirmBench"
              }
              onOpenChange={(v) => setDrawerOpen(v)}
              onDataUpdate={setFirmBenchData}
            />
            <UpSetPlot benchmark="FirmBench" tableData={firmBenchData} />
          </TabsContent>

          <TabsContent value="firmbenchx" className="space-y-4">
            <BugTable
              benchmark="FirmBenchX"
              openDrawer={
                drawerOpen === true && drawerSelectedBenchmark === "FirmBenchX"
              }
              onOpenChange={(v) => setDrawerOpen(v)}
              onDataUpdate={setFirmBenchXData}
            />
            <UpSetPlot benchmark="FirmBenchX" tableData={firmBenchXData} />
          </TabsContent>

          <TabsContent value="firmbenchdma" className="space-y-4">
            <BugTable
              benchmark="FirmBenchDMA"
              openDrawer={
                drawerOpen === true &&
                drawerSelectedBenchmark === "FirmBenchDMA"
              }
              onOpenChange={(v) => setDrawerOpen(v)}
              onDataUpdate={setFirmBenchDMAData}
            />
            <UpSetPlot benchmark="FirmBenchDMA" tableData={firmBenchDMAData} />
          </TabsContent>
        </Tabs>
      </Main>
    </>
  );
}
