// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/OWNER/jyoshin/internal/sensors"
)

// SelfOverhead reports Jyōshin's own resource utilization and cgroup limits.
type SelfOverhead struct {
	PID          int     `json:"pid"`
	NumGoroutine int     `json:"num_goroutine"`
	RSSBytes     uint64  `json:"rss_bytes"`
	VSizeBytes   uint64  `json:"vsize_bytes"`
	CPUPercent   float64 `json:"cpu_percent"`
	CgroupLimit  string  `json:"cgroup_limit,omitempty"`
	Nice         int     `json:"nice"`
}

// Supervisor manages sensor lifecycle, isolation, circuit breakers, and self-overhead.
type Supervisor struct {
	registry    *sensors.Registry
	logger      *slog.Logger
	mu          sync.RWMutex
	states      map[string]*sensors.SensorState
	lastObs     map[string]sensors.Observation
	wg          sync.WaitGroup
	cancel      context.CancelFunc
	running     bool
	prevCPUTime time.Duration
	prevSample  time.Time
}

// New creates a Supervisor with the provided sensor registry.
func New(registry *sensors.Registry, logger *slog.Logger) *Supervisor {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Supervisor{
		registry: registry,
		logger:   logger,
		states:   make(map[string]*sensors.SensorState),
		lastObs:  make(map[string]sensors.Observation),
	}

	for _, sensor := range registry.All() {
		s.states[sensor.Name()] = &sensors.SensorState{
			Name:         sensor.Name(),
			Interval:     sensor.Interval(),
			BreakerState: sensors.BreakerClosed,
		}
	}

	return s
}

// LowerPriority lowers the process priority to minimize host disturbance.
// Principle 3: NEVER HARM THE HOST. Low priority (nice 19 within 0..19, ionice idle where available).
func (s *Supervisor) LowerPriority() {
	// Set nice to 19 (highest unprivileged niceness / lowest scheduling priority within 0..19)
	targetNice := 19
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, targetNice)

	// Try setting ionice to idle/best-effort class via ioprio_set (SYS_ioprio_set) if linux
	const (
		ioprioClassShift = 13
		ioprioClassIdle  = 3
		ioprioWhoProcess = 1
	)
	idlePrio := (ioprioClassIdle << ioprioClassShift)
	_, _, _ = syscall.Syscall(syscall.SYS_IOPRIO_SET, uintptr(ioprioWhoProcess), 0, uintptr(idlePrio))
}

// Start begins independent collection loops for each sensor.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.prevSample = time.Now()
	s.mu.Unlock()

	s.LowerPriority()
	s.logger.Info("supervisor started; priority lowered")

	for _, sensor := range s.registry.All() {
		s.wg.Add(1)
		go s.runSensorLoop(ctx, sensor)
	}

	return nil
}

// Stop gracefully stops all sensor loops.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()

	s.wg.Wait()
	s.logger.Info("supervisor stopped")
	return nil
}

func (s *Supervisor) runSensorLoop(ctx context.Context, sensor sensors.Sensor) {
	defer s.wg.Done()

	// Initial run immediately
	s.executeSensor(ctx, sensor)

	ticker := time.NewTicker(sensor.Interval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.executeSensor(ctx, sensor)
		}
	}
}

func (s *Supervisor) executeSensor(ctx context.Context, sensor sensors.Sensor) {
	name := sensor.Name()

	s.mu.Lock()
	state, exists := s.states[name]
	if !exists {
		state = &sensors.SensorState{
			Name:         name,
			Interval:     sensor.Interval(),
			BreakerState: sensors.BreakerClosed,
		}
		s.states[name] = state
	}

	now := time.Now()
	if state.BreakerState == sensors.BreakerOpen {
		if now.Before(state.NextAllowedRun) {
			s.mu.Unlock()
			return // Breaker open, backoff in progress
		}
		state.BreakerState = sensors.BreakerHalfOpen
	}
	s.mu.Unlock()

	// Per-run timeout is min(sensor.Interval()/2, 10s) with 3s floor
	timeout := 10 * time.Second
	if half := sensor.Interval() / 2; half > 3*time.Second && half < timeout {
		timeout = half
	}

	obs, err := s.RunSensorSafe(ctx, sensor, timeout)

	s.mu.Lock()
	defer s.mu.Unlock()

	state.TotalRuns++
	state.LastRun = now
	state.LastDuration = obs.Duration

	if err != nil || obs.Status == sensors.StatusError {
		state.ConsecutiveFail++
		state.TotalFailures++
		if err != nil {
			state.LastError = err.Error()
		} else {
			state.LastError = obs.Reason
		}

		// Exponential backoff & Circuit Breaker: trip open after 3 consecutive failures
		if state.ConsecutiveFail >= 3 {
			state.BreakerState = sensors.BreakerOpen
			backoffSec := math.Pow(2, float64(state.ConsecutiveFail)) * 5
			if backoffSec > 300 {
				backoffSec = 300
			}
			state.NextAllowedRun = now.Add(time.Duration(backoffSec) * time.Second)
			s.logger.Warn("sensor circuit breaker tripped open", "sensor", name, "consecutive_failures", state.ConsecutiveFail, "backoff_seconds", backoffSec)
		}
	} else {
		// Successful or graceful unknown
		state.ConsecutiveFail = 0
		state.LastError = ""
		state.BreakerState = sensors.BreakerClosed
		s.lastObs[name] = obs
	}
}

// RunSensorSafe executes a sensor with isolated timeout and panic recovery.
// Principle 4: ISOLATION.
func (s *Supervisor) RunSensorSafe(ctx context.Context, sensor sensors.Sensor, timeout time.Duration) (obs sensors.Observation, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sensor panic recovered: %v", r)
			obs = sensors.Observation{
				SensorName: sensor.Name(),
				Timestamp:  time.Now().UTC(),
				Status:     sensors.StatusError,
				Reason:     fmt.Sprintf("panic: %v", r),
			}
			s.logger.Error("sensor panicked", "sensor", sensor.Name(), "panic", r)
		}
	}()

	sensorCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	obs, err = sensor.Collect(sensorCtx)
	if obs.Duration == 0 {
		obs.Duration = time.Since(start)
	}
	return obs, err
}

// GetObservation returns the most recent observation for a sensor.
func (s *Supervisor) GetObservation(name string) (sensors.Observation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	obs, ok := s.lastObs[name]
	return obs, ok
}

// GetSensorStates returns health/metrics for all sensors.
func (s *Supervisor) GetSensorStates() []sensors.SensorState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]sensors.SensorState, 0, len(s.states))
	for _, st := range s.states {
		list = append(list, *st)
	}
	return list
}

// GetSelfOverhead computes own process metrics (RSS, CPU%, cgroups, nice).
func (s *Supervisor) GetSelfOverhead() SelfOverhead {
	pid := os.Getpid()
	rawPrio, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0)
	nice := 0
	if err == nil {
		nice = 20 - rawPrio
		if nice < -20 {
			nice = -20
		} else if nice > 19 {
			nice = 19
		}
	}

	overhead := SelfOverhead{
		PID:          pid,
		NumGoroutine: runtime.NumGoroutine(),
		Nice:         nice,
	}

	// Read /proc/self/statm for memory
	if statmData, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(statmData))
		pageSize := uint64(os.Getpagesize())
		if len(fields) >= 2 {
			vsizePages, _ := strconv.ParseUint(fields[0], 10, 64)
			rssPages, _ := strconv.ParseUint(fields[1], 10, 64)
			overhead.VSizeBytes = vsizePages * pageSize
			overhead.RSSBytes = rssPages * pageSize
		}
	}

	// Read cgroup limit if present
	if cgData, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		overhead.CgroupLimit = strings.TrimSpace(string(cgData))
	}

	// Compute CPU % based on /proc/self/stat
	if statData, err := os.ReadFile("/proc/self/stat"); err == nil {
		fields := strings.Fields(string(statData))
		if len(fields) > 14 {
			utime, _ := strconv.ParseUint(fields[13], 10, 64)
			stime, _ := strconv.ParseUint(fields[14], 10, 64)
			totalTicks := utime + stime
			// Standard Linux clock ticks is 100 per sec
			cpuDuration := time.Duration(totalTicks*10) * time.Millisecond

			s.mu.Lock()
			now := time.Now()
			elapsed := now.Sub(s.prevSample)
			if elapsed > 0 && s.prevCPUTime > 0 {
				deltaCPU := cpuDuration - s.prevCPUTime
				overhead.CPUPercent = math.Max(0.0, float64(deltaCPU)/float64(elapsed)*100.0)
			}
			s.prevCPUTime = cpuDuration
			s.prevSample = now
			s.mu.Unlock()
		}
	}

	return overhead
}
