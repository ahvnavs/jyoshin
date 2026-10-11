// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/sensors"
)

type dummySensor struct {
	name      string
	interval  time.Duration
	collectFn func(ctx context.Context) (sensors.Observation, error)
}

func (d *dummySensor) Name() string            { return d.name }
func (d *dummySensor) Interval() time.Duration { return d.interval }
func (d *dummySensor) Collect(ctx context.Context) (sensors.Observation, error) {
	return d.collectFn(ctx)
}

func TestSupervisor_PanicRecovery(t *testing.T) {
	reg := sensors.NewRegistry()
	panicSensor := &dummySensor{
		name:     "panicker",
		interval: 100 * time.Millisecond,
		collectFn: func(ctx context.Context) (sensors.Observation, error) {
			panic("simulated fatal crash")
		},
	}
	_ = reg.Register(panicSensor)

	sup := New(reg, nil)
	obs, err := sup.RunSensorSafe(context.Background(), panicSensor, 1*time.Second)

	if err == nil {
		t.Fatal("expected error from panic, got nil")
	}
	if obs.Status != sensors.StatusError {
		t.Fatalf("expected status error, got %s", obs.Status)
	}
}

func TestSupervisor_HangIsolation(t *testing.T) {
	reg := sensors.NewRegistry()

	// Hanging sensor sleeps until ctx cancelled
	hangSensor := &dummySensor{
		name:     "hanger",
		interval: 50 * time.Millisecond,
		collectFn: func(ctx context.Context) (sensors.Observation, error) {
			<-ctx.Done()
			return sensors.Observation{
				SensorName: "hanger",
				Status:     sensors.StatusUnknown,
				Reason:     "timed out",
			}, ctx.Err()
		},
	}

	// Fast healthy sensor
	fastSensor := &dummySensor{
		name:     "fast",
		interval: 50 * time.Millisecond,
		collectFn: func(ctx context.Context) (sensors.Observation, error) {
			return sensors.Observation{
				SensorName: "fast",
				Status:     sensors.StatusSuccess,
			}, nil
		},
	}

	_ = reg.Register(hangSensor)
	_ = reg.Register(fastSensor)

	sup := New(reg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Verify that fast sensor completes execution even while hanging sensor is stuck
	time.Sleep(100 * time.Millisecond)

	obsFast, foundFast := sup.GetObservation("fast")
	if !foundFast || obsFast.Status != sensors.StatusSuccess {
		t.Fatalf("fast sensor failed to record observation: found=%v, obs=%+v", foundFast, obsFast)
	}

	_ = sup.Stop()
}

func TestSupervisor_CircuitBreaker(t *testing.T) {
	reg := sensors.NewRegistry()
	failCount := 0
	failingSensor := &dummySensor{
		name:     "faulty",
		interval: 10 * time.Millisecond,
		collectFn: func(ctx context.Context) (sensors.Observation, error) {
			failCount++
			return sensors.Observation{SensorName: "faulty", Status: sensors.StatusError}, errors.New("io error")
		},
	}
	_ = reg.Register(failingSensor)

	sup := New(reg, nil)

	// Execute failing sensor 3 times manually to trip the circuit breaker
	ctx := context.Background()
	sup.executeSensor(ctx, failingSensor)
	sup.executeSensor(ctx, failingSensor)
	sup.executeSensor(ctx, failingSensor)

	states := sup.GetSensorStates()
	var faultyState *sensors.SensorState
	for i := range states {
		if states[i].Name == "faulty" {
			faultyState = &states[i]
			break
		}
	}

	if faultyState == nil {
		t.Fatal("faulty sensor state not found")
	}

	if faultyState.BreakerState != sensors.BreakerOpen {
		t.Fatalf("expected circuit breaker open, got %s", faultyState.BreakerState)
	}
	if faultyState.ConsecutiveFail != 3 {
		t.Fatalf("expected 3 consecutive failures, got %d", faultyState.ConsecutiveFail)
	}
}

func TestSupervisor_SelfOverhead(t *testing.T) {
	reg := sensors.NewRegistry()
	sup := New(reg, nil)

	sup.LowerPriority()
	overhead := sup.GetSelfOverhead()

	if overhead.PID <= 0 {
		t.Fatalf("invalid PID in self overhead: %d", overhead.PID)
	}
	if overhead.Nice < 10 {
		t.Logf("nice value is %d (may be unprivileged or limited by sandbox)", overhead.Nice)
	}
}
