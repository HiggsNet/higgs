package photonclient_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient"
	"github.com/HiggsNet/photon/internal/photonclient/testkit"
)

func TestResourcesValidateRejectsPartialWiringAndBadMTU(t *testing.T) {
	if err := (photonclient.Resources{}).Validate(); err == nil {
		t.Fatal("empty Resources.Validate succeeded")
	}
	resources := testResources(1200)
	if err := resources.Validate(); err == nil {
		t.Fatal("Resources.Validate accepted MTU below IPv6 minimum")
	}
	resources = testResources(1400)
	if err := resources.Validate(); err != nil {
		t.Fatalf("Resources.Validate: %v", err)
	}
}

func TestRuntimeStartStopClosesInjectedResources(t *testing.T) {
	resources := testResources(1400)
	workload := newFakeWorkload()
	runtime := photonclient.NewRuntime(resources, workload)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runtime.Status().State; got != photonclient.RuntimeRunning {
		t.Fatalf("state = %s", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if got := runtime.Status().State; got != photonclient.RuntimeStopped {
		t.Fatalf("state = %s", got)
	}
	if !resources.Tunnel.(*testkit.MemoryTunnel).Closed() ||
		!resources.Datagram.(*testkit.MemoryDatagram).Closed() ||
		!resources.Networks.(*testkit.MemoryNetworkObserver).Closed() ||
		!resources.States.(*testkit.MemoryStateSource).Closed() {
		t.Fatal("runtime did not close every owned resource")
	}
}

func TestRuntimeUnexpectedWorkloadExitFailsClosed(t *testing.T) {
	resources := testResources(1400)
	workload := newFakeWorkload()
	runtime := photonclient.NewRuntime(resources, workload)
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	workload.exit(errors.New("receive loop failed"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Wait(ctx); err == nil {
		t.Fatal("Runtime.Wait returned nil after workload failure")
	}
	status := runtime.Status()
	if status.State != photonclient.RuntimeFailed || status.Error == "" {
		t.Fatalf("status = %#v", status)
	}
}

func TestRuntimeSerializesConcurrentStartAndStop(t *testing.T) {
	resources := testResources(1400)
	workload := newBlockingStartWorkload()
	runtime := photonclient.NewRuntime(resources, workload)
	startResult := make(chan error, 1)
	go func() { startResult <- runtime.Start(context.Background()) }()
	<-workload.startEntered

	stopResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { stopResult <- runtime.Stop(ctx) }()
	select {
	case err := <-stopResult:
		t.Fatalf("Stop returned before Start completed: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(workload.allowStart)
	if err := <-startResult; err != nil {
		t.Fatal(err)
	}
	if err := <-stopResult; err != nil {
		t.Fatal(err)
	}
	if got := runtime.Status().State; got != photonclient.RuntimeStopped {
		t.Fatalf("state = %s", got)
	}
}

func testResources(mtu int) photonclient.Resources {
	return photonclient.Resources{
		Tunnel:   testkit.NewMemoryTunnel("memory0", mtu),
		Datagram: testkit.NewMemoryDatagram(),
		Networks: testkit.NewMemoryNetworkObserver(photonclient.NetworkChange{}),
		Keys:     testkit.NewMemoryKeyStore(),
		States:   testkit.NewMemoryStateSource(photonclient.StateSnapshot{}),
		Clock:    testkit.NewManualClock(time.Unix(0, 0)),
	}
}

type fakeWorkload struct {
	mu      sync.Mutex
	started bool
	result  chan error
	once    sync.Once
}

func newFakeWorkload() *fakeWorkload {
	return &fakeWorkload{result: make(chan error, 1)}
}

func (w *fakeWorkload) Start(_ context.Context, _ photonclient.Resources) error {
	w.mu.Lock()
	w.started = true
	w.mu.Unlock()
	return nil
}

func (w *fakeWorkload) Stop(_ context.Context) error {
	w.exit(context.Canceled)
	return nil
}

func (w *fakeWorkload) Wait() error { return <-w.result }

func (w *fakeWorkload) exit(err error) {
	w.once.Do(func() { w.result <- err })
}

type blockingStartWorkload struct {
	*fakeWorkload
	startEntered chan struct{}
	allowStart   chan struct{}
}

func newBlockingStartWorkload() *blockingStartWorkload {
	return &blockingStartWorkload{
		fakeWorkload: newFakeWorkload(),
		startEntered: make(chan struct{}),
		allowStart:   make(chan struct{}),
	}
}

func (w *blockingStartWorkload) Start(_ context.Context, _ photonclient.Resources) error {
	close(w.startEntered)
	<-w.allowStart
	return nil
}
