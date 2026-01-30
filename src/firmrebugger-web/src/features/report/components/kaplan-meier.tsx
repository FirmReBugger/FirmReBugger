import React, { useMemo, useState } from 'react'
import { VegaLite } from 'react-vega'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { computeKaplanFromTimes, type KaplanSeries } from '../utils/kaplan'

type KMProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  bugId: string
  fuzzerRuns: Record<string, Array<{ run: string; reached?: number | null; triggered?: number | null; detected?: number | null }>>
  metric?: 'detected' | 'reached' | 'triggered'
  onMetricChange?: (metric: 'detected' | 'reached' | 'triggered') => void
}

const COLORS = [
  '#1f77b4',
  '#ff7f0e',
  '#2ca02c',
  '#d62728',
  '#9467bd',
  '#8c564b',
  '#e377c2',
  '#7f7f7f',
  '#bcbd22',
  '#17becf',
]

const METRIC_LABELS = {
  reached: 'Reached (R)',
  triggered: 'Triggered (T)',
  detected: 'Detected (D)'
}

export function KaplanMeier({ open, onOpenChange, bugId, fuzzerRuns, metric = 'reached', onMetricChange }: KMProps) {
  const fuzzers = useMemo(() => Object.keys(fuzzerRuns).filter(k => Array.isArray(fuzzerRuns[k]) && fuzzerRuns[k].length > 0), [fuzzerRuns])
  const [selected, setSelected] = useState<string[]>([])

  React.useEffect(() => {
    setSelected(fuzzers)
  }, [bugId, fuzzers])

  const trialTime = useMemo(() => {
    let maxTime = 0
    fuzzers.forEach((f) => {
      const runs = fuzzerRuns[f] || []
      runs.forEach(r => {
        const val = r[metric]
        if (val !== null && val !== undefined && Number.isFinite(val)) {
          maxTime = Math.max(maxTime, val)
        }
      })
    })
    return maxTime > 0 ? maxTime : 24 * 3600
  }, [fuzzerRuns, metric, fuzzers])

  const series: KaplanSeries[] = useMemo(() => {
    return fuzzers.map((f) => {
      const runs = fuzzerRuns[f] || []
      const times = runs.map(r => r[metric] ?? null)
      const s = computeKaplanFromTimes(times, trialTime)
      s.name = f
      return s
    })
  }, [fuzzerRuns, metric, fuzzers, trialTime])

  const kmData = useMemo(() => {
    // flattened step rows with fuzzer name
    const rows: Array<{ fuzzer: string; time: number; survival: number }> = []
    series.forEach(s => {
      if (!selected.includes(s.name)) return
      s.step.forEach(pt => {
        if (!Number.isFinite(pt.time) || !Number.isFinite(pt.survival)) return
        const time = Math.max(0, pt.time)
        const survival = Math.max(0, Math.min(1, pt.survival))
        rows.push({ fuzzer: s.name, time, survival })
      })
    })
    return rows
  }, [series, selected])

  const censoredData = useMemo(() => {
    const rows: Array<{ fuzzer: string; time: number; survival: number }> = []
    series.forEach(s => {
      if (!selected.includes(s.name)) return
      s.censored.forEach(pt => {
        if (!Number.isFinite(pt.time) || !Number.isFinite(pt.survival)) return
        const time = Math.max(0, pt.time)
        const survival = Math.max(0, Math.min(1, pt.survival))
        rows.push({ fuzzer: s.name, time, survival })
      })
    })
    return rows
  }, [series, selected])

  const xMax = useMemo(() => {
    const maxFromSteps = Math.max(...series.flatMap(s => s.step.map(pt => pt.time)).filter(Number.isFinite))
    return maxFromSteps > 0 ? maxFromSteps : 1
  }, [series])

  const colorScale = useMemo(() => {
    const domain = fuzzers
    const range = fuzzers.map((_, idx) => COLORS[idx % COLORS.length])
    return { domain, range }
  }, [fuzzers])

  const spec = {
    width: 500,
    height: 280,
    layer: [
      {
        data: { name: 'km' },
        mark: { type: 'line' as const, interpolate: 'step-after' as const }, 
        encoding: {
          x: { field: 'time', type: 'quantitative' as const, title: 'Time (hours)', scale: { domain: [0, xMax] } },
          y: { field: 'survival', type: 'quantitative' as const, title: 'Survival', scale: { domain: [0, 1] } },
          color: { 
            field: 'fuzzer', 
            type: 'nominal' as const, 
            legend: null,
            scale: { domain: colorScale.domain, range: colorScale.range }
          }, 
          tooltip: [
            { field: 'fuzzer', type: 'nominal' as const },
            { field: 'time', type: 'quantitative' as const },
            { field: 'survival', type: 'quantitative' as const },
          ],
        },
      },
      {
        data: { name: 'censored' },
        mark: { type: 'point' as const, shape: 'triangle', size: 60 }, 
        encoding: {
          x: { field: 'time', type: 'quantitative' as const, scale: { domain: [0, xMax] } },
          y: { field: 'survival', type: 'quantitative' as const },
          color: { 
            field: 'fuzzer', 
            type: 'nominal' as const, 
            legend: null,
            scale: { domain: colorScale.domain, range: colorScale.range }
          },
          tooltip: [
            { field: 'fuzzer', type: 'nominal' as const },
            { field: 'time', type: 'quantitative' as const },
          ],
        },
      },
    ],
    config: {
      point: { filled: true, size: 60 },
    },
  };

  React.useEffect(() => {
    if (!open) return
    setTimeout(() => {
      const anyNonFinite = [...kmData, ...censoredData].some(d => !Number.isFinite(d.time) || !Number.isFinite(d.survival))
      if (anyNonFinite) console.warn('Kaplan data contains non-finite values')
      if (kmData.length === 0) console.info('Kaplan: no kmData rows for selected fuzzers')
    }, 0)
  }, [open, series, kmData, censoredData, xMax])

  const handlePrevMetric = () => {
    if (!onMetricChange) return
    const metrics: Array<'reached' | 'triggered' | 'detected'> = ['reached', 'triggered', 'detected']
    const currentIndex = metrics.indexOf(metric)
    const prevIndex = (currentIndex - 1 + metrics.length) % metrics.length
    onMetricChange(metrics[prevIndex])
  }

  const handleNextMetric = () => {
    if (!onMetricChange) return
    const metrics: Array<'reached' | 'triggered' | 'detected'> = ['reached', 'triggered', 'detected']
    const currentIndex = metrics.indexOf(metric)
    const nextIndex = (currentIndex + 1) % metrics.length
    onMetricChange(metrics[nextIndex])
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
          className="!max-w-2xl w-[95vw] max-h-[95vh] overflow-auto">
        <DialogHeader>
          <DialogTitle>Kaplan-Meier: {bugId}</DialogTitle>
          <DialogDescription>
            Survival curves for different fuzzers. X axis is time in hours.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 flex-wrap">
              {fuzzers.map((f, idx) => (
                <button
                  key={f}
                  onClick={() => {
                    setSelected(prev => prev.includes(f) ? prev.filter(p => p !== f) : [...prev, f])
                  }}
                  className={`inline-flex items-center gap-2 text-sm px-3 py-1.5 rounded-md border transition-colors ${
                    selected.includes(f)
                      ? 'bg-primary/10 border-primary text-primary'
                      : 'bg-muted border-muted-foreground/20 text-muted-foreground hover:bg-muted/80'
                  }`}
                >
                  <span style={{ width: 12, height: 12, background: COLORS[idx % COLORS.length], display: 'inline-block', borderRadius: 2 }} />
                  <span className="truncate max-w-xs">{f}</span>
                </button>
              ))}
            </div>
          </div>

          <div>
            {kmData.length === 0 ? (
              <div className="text-sm text-muted-foreground p-6 text-center">No survival data available for the selected fuzzers.</div>
            ) : (
              <VegaLite spec={spec} data={{ km: kmData, censored: censoredData }} />
            )}
          </div>

          <div className="text-xs text-muted-foreground">
            {series.filter(s => selected.includes(s.name)).map(s => (
              <div key={s.name} className="flex items-center gap-4">
                <div style={{ width: 10, height: 10, background: COLORS[fuzzers.indexOf(s.name) % COLORS.length], borderRadius: 2 }} />
                <div>
                  <strong>{s.name}</strong> — RMST: {s.stats.rmst ? s.stats.rmst.toFixed(2) : 'N/A'}h, n={s.stats.n}, events={s.stats.events}
                </div>
              </div>
            ))}
          </div>

          {onMetricChange && (
            <div className="flex items-center justify-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handlePrevMetric}
                className="h-8 px-2"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm font-semibold min-w-[120px] text-center">
                {METRIC_LABELS[metric]}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={handleNextMetric}
                className="h-8 px-2"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )}

        </div>
      </DialogContent>
    </Dialog>
  )
}