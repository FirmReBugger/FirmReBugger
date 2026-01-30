export type KaplanSeries = {
  name: string
  step: Array<{ time: number; survival: number }>
  censored: Array<{ time: number; survival: number }>
  stats: { rmst: number | null; n: number; events: number }
}

export function computeKaplanFromTimes(
  timesInSeconds: Array<number | null>,
  trialTimeSeconds?: number
): KaplanSeries {
  const maxObserved = Math.max(...(timesInSeconds.filter((t) => t !== null) as number[]), 0)
  const defaultTrial = Math.max(maxObserved, 24 * 3600)
  const trial = (trialTimeSeconds ?? defaultTrial) / 3600 // hours
  
  const times = timesInSeconds.map((t) => {
    if (t === null || t === undefined) return null
    if (typeof t !== 'number' || !isFinite(t)) return null
    return t / 3600
  })
  
  const T = times.map((t) => (t === null ? trial : t))
  const E = times.map((t) => (t === null ? 0 : 1))
  const n = T.length
  const eventsTotal = E.reduce<number>((a, b) => a + b, 0)
  
  const timeline = Array.from(new Set(T.filter((v) => Number.isFinite(v)))).sort((a, b) => a - b)
  
  let atRisk = n
  let survivalProb = 1
  const step: Array<{ time: number; survival: number }> = [{ time: 0, survival: 1 }]
  
  for (const t of timeline) {
    const eventsHere = T.reduce((acc, val, idx) => (val === t && E[idx] === 1 ? acc + 1 : acc), 0)
    const censHere = T.reduce((acc, val, idx) => (val === t && E[idx] === 0 ? acc + 1 : acc), 0)
    
    if (eventsHere > 0) {
      if (atRisk > 0) {
        survivalProb = survivalProb * (1 - eventsHere / atRisk)
        if (!isFinite(survivalProb) || Number.isNaN(survivalProb)) {
          survivalProb = 0
        }
      }
      step.push({ time: t, survival: survivalProb })
    }
    
    atRisk -= eventsHere + censHere
    if (atRisk < 0) atRisk = 0
  }
  
  step.push({ time: trial, survival: survivalProb })
  
  const censored: Array<{ time: number; survival: number }> = []
  
  function survivalAt(t: number) {
    for (let i = step.length - 1; i >= 0; i--) {
      if (step[i].time <= t) return step[i].survival
    }
    return 1
  }
  
  timesInSeconds.forEach((orig) => {
    if (orig === null) {
      const t = trial
      censored.push({ time: t, survival: survivalAt(t) })
    }
  })
  
  let rmst = 0
  for (let i = 0; i < step.length - 1; i++) {
    const t1 = step[i].time
    const t2 = Math.min(step[i + 1].time, trial)
    const survivalValue = step[i].survival
    
    if (t2 > t1) {
      rmst += (t2 - t1) * survivalValue
    }
    
    if (t2 >= trial) break
  }
  
  return {
    name: 'series',
    step,
    censored,
    stats: { rmst: isFinite(rmst) ? rmst : null, n, events: eventsTotal },
  }
}