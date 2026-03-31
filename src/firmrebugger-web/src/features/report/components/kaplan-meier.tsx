import React, { useMemo, useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { ChevronLeft, ChevronRight, Download } from 'lucide-react'
import { toast } from 'sonner'
import { computeKaplanFromTimes, type KaplanSeries } from '../utils/kaplan'

type KMProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  bugId: string
  fuzzerRuns: Record<
    string,
    Array<{
      run: string
      reached?: number | null
      triggered?: number | null
      detected?: number | null
    }>
  >
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
  detected: 'Detected (D)',
}

export function KaplanMeier({
  open,
  onOpenChange,
  bugId,
  fuzzerRuns,
  metric = 'detected',
  onMetricChange,
}: KMProps) {
  const fuzzers = useMemo(
    () =>
      Object.keys(fuzzerRuns).filter(
        (k) => Array.isArray(fuzzerRuns[k]) && fuzzerRuns[k].length > 0,
      ),
    [fuzzerRuns],
  )

  const [selected, setSelected] = useState<string[]>([])
  const chartSvgRef = React.useRef<SVGSVGElement | null>(null)
  const [chartWidth, setChartWidth] = useState(980)
  const [exporting, setExporting] = useState(false)

  React.useEffect(() => {
    setSelected(fuzzers)
  }, [bugId, fuzzers])

  React.useEffect(() => {
    if (open) {
      setSelected(fuzzers)
    }
  }, [open, fuzzers])

  React.useEffect(() => {
    if (!open) return

    const updateWidth = () => {
      const next = Math.max(640, Math.min(980, Math.floor(window.innerWidth - 120)))
      setChartWidth(next)
    }

    updateWidth()
    window.addEventListener('resize', updateWidth)
    return () => {
      window.removeEventListener('resize', updateWidth)
    }
  }, [open])

  const trialTime = useMemo(() => {
    let maxTime = 0
    fuzzers.forEach((f) => {
      const runs = fuzzerRuns[f] || []
      runs.forEach((r) => {
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
      const times = runs.map((r) => r[metric] ?? null)
      const s = computeKaplanFromTimes(times, trialTime)
      s.name = f
      return s
    })
  }, [fuzzerRuns, metric, fuzzers, trialTime])

  const xMax = useMemo(() => {
    const maxFromSteps = Math.max(
      ...series.flatMap((s) => s.step.map((pt) => pt.time)).filter(Number.isFinite),
    )
    return maxFromSteps > 0 ? maxFromSteps : 1
  }, [series])

  const colorScale = useMemo(() => {
    const domain = fuzzers
    const range = fuzzers.map((_, idx) => COLORS[idx % COLORS.length])
    return { domain, range }
  }, [fuzzers])

  const selectedSeries = useMemo(
    () => series.filter((s) => selected.includes(s.name)),
    [series, selected],
  )

  const plotHeight = 390
  const margin = { top: 16, right: 20, bottom: 44, left: 56 }
  const innerWidth = Math.max(420, chartWidth - margin.left - margin.right)
  const innerHeight = Math.max(220, plotHeight - margin.top - margin.bottom)

  const xTicks = useMemo(() => {
    const max = xMax > 0 ? xMax : 1
    return [0, max * 0.25, max * 0.5, max * 0.75, max]
  }, [xMax])

  const yTicks = [0, 0.25, 0.5, 0.75, 1]

  const xScale = (v: number) =>
    (Math.max(0, v) / (xMax > 0 ? xMax : 1)) * innerWidth
  const yScale = (v: number) =>
    (1 - Math.max(0, Math.min(1, v))) * innerHeight

  const mkStepPath = (points: Array<{ time: number; survival: number }>) => {
    const clean = points
      .filter((pt) => Number.isFinite(pt.time) && Number.isFinite(pt.survival))
      .map((pt) => ({
        time: Math.max(0, pt.time),
        survival: Math.max(0, Math.min(1, pt.survival)),
      }))
      .sort((a, b) => a.time - b.time)

    if (clean.length === 0) return ''

    let d = `M ${xScale(clean[0].time)} ${yScale(clean[0].survival)}`
    for (let i = 1; i < clean.length; i++) {
      d += ` H ${xScale(clean[i].time)} V ${yScale(clean[i].survival)}`
    }
    return d
  }

  const handlePrevMetric = () => {
    if (!onMetricChange) return
    const metrics: Array<'reached' | 'triggered' | 'detected'> = [
      'reached',
      'triggered',
      'detected',
    ]
    const currentIndex = metrics.indexOf(metric)
    const prevIndex = (currentIndex - 1 + metrics.length) % metrics.length
    onMetricChange(metrics[prevIndex])
  }

  const handleNextMetric = () => {
    if (!onMetricChange) return
    const metrics: Array<'reached' | 'triggered' | 'detected'> = [
      'reached',
      'triggered',
      'detected',
    ]
    const currentIndex = metrics.indexOf(metric)
    const nextIndex = (currentIndex + 1) % metrics.length
    onMetricChange(metrics[nextIndex])
  }

  const handleExportPdf = async () => {
    if (!chartSvgRef.current || selectedSeries.length === 0) return

    setExporting(true)
    try {
      const serializer = new XMLSerializer()
      let svgText = serializer.serializeToString(chartSvgRef.current)

      if (!svgText.includes('xmlns="http://www.w3.org/2000/svg"')) {
        svgText = svgText.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"')
      }

      if (!svgText.includes('xmlns:xlink="http://www.w3.org/1999/xlink"')) {
        svgText = svgText.replace('<svg', '<svg xmlns:xlink="http://www.w3.org/1999/xlink"')
      }

      const svgBlob = new Blob([svgText], {
        type: 'image/svg+xml;charset=utf-8',
      })
      const svgUrl = URL.createObjectURL(svgBlob)

      const image = new Image()
      image.decoding = 'async'

      await new Promise<void>((resolve, reject) => {
        image.onload = () => resolve()
        image.onerror = () =>
          reject(new Error('Unable to render survival curve image for export'))
        image.src = svgUrl
      })

      const scale = 2
      const canvas = document.createElement('canvas')
      canvas.width = Math.floor(chartWidth * scale)
      canvas.height = Math.floor(plotHeight * scale)

      const ctx = canvas.getContext('2d')
      if (!ctx) {
        URL.revokeObjectURL(svgUrl)
        throw new Error('Unable to initialize PDF canvas context')
      }

      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.drawImage(image, 0, 0, canvas.width, canvas.height)
      URL.revokeObjectURL(svgUrl)

      const pngData = canvas.toDataURL('image/png')
      const { jsPDF } = await import('jspdf')
      const pdf = new jsPDF({
        orientation: canvas.width >= canvas.height ? 'landscape' : 'portrait',
        unit: 'pt',
        format: [canvas.width, canvas.height],
      })

      pdf.addImage(pngData, 'PNG', 0, 0, canvas.width, canvas.height)
      pdf.save(`bug_${bugId}_${metric}_survival_curve.pdf`)
      toast.success('Survival curve PDF downloaded')
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : 'Failed to export survival curve PDF',
      )
    } finally {
      setExporting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="!max-w-none max-h-[92vh] flex flex-col overflow-auto"
        style={{ width: `${chartWidth + 56}px`, maxWidth: '95vw' }}
      >
        <DialogHeader>
          <DialogTitle>Bug Survival Curve: {bugId}</DialogTitle>
          <DialogDescription>
            Toggle fuzzers and metrics below the chart.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={handleExportPdf}
              disabled={exporting || selectedSeries.length === 0}
            >
              <Download className="h-4 w-4 mr-2" />
              {exporting ? 'Exporting...' : 'Export PDF'}
            </Button>
          </div>

          <div className="w-full relative">
            <div className="w-full overflow-auto">
              {selectedSeries.length === 0 ? (
                <div className="text-sm text-muted-foreground p-8 text-center">
                  No survival data available for the selected fuzzers and metric.
                </div>
              ) : (
                <div
                  className="w-full flex justify-center"
                  style={{ minWidth: `${chartWidth}px` }}
                >
                  <svg
                    ref={chartSvgRef}
                    width={chartWidth}
                    height={plotHeight}
                    role="img"
                    aria-label="Kaplan-Meier survival chart"
                  >
                    <g transform={`translate(${margin.left},${margin.top})`}>
                      <rect
                        x={0}
                        y={0}
                        width={innerWidth}
                        height={innerHeight}
                        fill="transparent"
                      />

                      {yTicks.map((t) => (
                        <line
                          key={`y-grid-${t}`}
                          x1={0}
                          y1={yScale(t)}
                          x2={innerWidth}
                          y2={yScale(t)}
                          stroke="currentColor"
                          strokeOpacity={0.12}
                        />
                      ))}

                      {xTicks.map((t, i) => (
                        <line
                          key={`x-grid-${i}`}
                          x1={xScale(t)}
                          y1={0}
                          x2={xScale(t)}
                          y2={innerHeight}
                          stroke="currentColor"
                          strokeOpacity={0.08}
                        />
                      ))}

                      <line
                        x1={0}
                        y1={innerHeight}
                        x2={innerWidth}
                        y2={innerHeight}
                        stroke="currentColor"
                        strokeOpacity={0.7}
                      />
                      <line
                        x1={0}
                        y1={0}
                        x2={0}
                        y2={innerHeight}
                        stroke="currentColor"
                        strokeOpacity={0.7}
                      />

                      {xTicks.map((t, i) => (
                        <g
                          key={`x-tick-${i}`}
                          transform={`translate(${xScale(t)},${innerHeight})`}
                        >
                          <line y2={6} stroke="currentColor" strokeOpacity={0.7} />
                          <text
                            y={20}
                            textAnchor="middle"
                            fontSize={11}
                            fill="currentColor"
                            opacity={0.8}
                          >
                            {t.toFixed(1)}
                          </text>
                        </g>
                      ))}

                      {yTicks.map((t) => (
                        <g key={`y-tick-${t}`} transform={`translate(0,${yScale(t)})`}>
                          <line x2={-6} stroke="currentColor" strokeOpacity={0.7} />
                          <text
                            x={-10}
                            dy="0.32em"
                            textAnchor="end"
                            fontSize={11}
                            fill="currentColor"
                            opacity={0.8}
                          >
                            {t.toFixed(2)}
                          </text>
                        </g>
                      ))}

                      {selectedSeries.map((s) => {
                        const color =
                          colorScale.range[
                            Math.max(0, colorScale.domain.indexOf(s.name)) %
                              colorScale.range.length
                          ]
                        const d = mkStepPath(s.step)
                        return d ? (
                          <path
                            key={`line-${s.name}`}
                            d={d}
                            fill="none"
                            stroke={color}
                            strokeWidth={2.2}
                          />
                        ) : null
                      })}

                      {selectedSeries.map((s) => {
                        const color =
                          colorScale.range[
                            Math.max(0, colorScale.domain.indexOf(s.name)) %
                              colorScale.range.length
                          ]
                        return (
                          <g key={`censored-${s.name}`}>
                            {(s.censored || []).map((pt, idx) => {
                              if (
                                !Number.isFinite(pt.time) ||
                                !Number.isFinite(pt.survival)
                              ) {
                                return null
                              }
                              const cx = xScale(pt.time)
                              const cy = yScale(pt.survival)
                              const tri = `${cx},${cy - 4} ${cx - 3.6},${cy + 3} ${cx + 3.6},${cy + 3}`
                              return (
                                <polygon
                                  key={`c-${s.name}-${idx}`}
                                  points={tri}
                                  fill={color}
                                  opacity={0.95}
                                />
                              )
                            })}
                          </g>
                        )
                      })}

                      <text
                        x={innerWidth / 2}
                        y={innerHeight + 36}
                        textAnchor="middle"
                        fontSize={12}
                        fill="currentColor"
                        opacity={0.9}
                      >
                        Time (hours)
                      </text>
                      <text
                        transform={`translate(${-44},${innerHeight / 2}) rotate(-90)`}
                        textAnchor="middle"
                        fontSize={12}
                        fill="currentColor"
                        opacity={0.9}
                      >
                        Survival Probability
                      </text>
                    </g>
                  </svg>
                </div>
              )}
            </div>
          </div>

          <div className="w-full flex justify-center">
            <div className="flex flex-col items-center gap-2">
              <div className="flex flex-wrap items-center justify-center gap-2">
                {fuzzers.map((f, idx) => (
                  <button
                    key={`toggle-${f}`}
                    onClick={() => {
                      setSelected((prev) =>
                        prev.includes(f) ? prev.filter((p) => p !== f) : [...prev, f],
                      )
                    }}
                    className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1 text-xs transition-colors ${
                      selected.includes(f)
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border bg-background text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    <span
                      style={{
                        width: 8,
                        height: 8,
                        background: COLORS[idx % COLORS.length],
                        display: 'inline-block',
                        borderRadius: 999,
                      }}
                    />
                    {f}
                  </button>
                ))}
              </div>

              {onMetricChange && (
                <div className="mt-1 flex items-center gap-2">
                  <button
                    className="h-7 w-7 rounded-md border border-border bg-background hover:bg-muted transition-colors inline-flex items-center justify-center"
                    onClick={handlePrevMetric}
                    aria-label="Previous metric"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </button>
                  <div className="text-sm font-medium min-w-[120px] text-center">
                    {METRIC_LABELS[metric]}
                  </div>
                  <button
                    className="h-7 w-7 rounded-md border border-border bg-background hover:bg-muted transition-colors inline-flex items-center justify-center"
                    onClick={handleNextMetric}
                    aria-label="Next metric"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
