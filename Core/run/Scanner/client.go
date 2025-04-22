package scanner

import (
	"escan/Common"
	"sync"
	"sync/atomic"
	"time"
)

type client struct {
	config    Config
	pool      *Pool
	deferFunc func()
}

type Config struct {
	DeepInspection     bool
	Timeout            time.Duration
	Threads            int
	Interval           time.Duration
	HostDiscoverClosed bool
}

func (c *client) Run() {
	c.pool.Run()
}

func (c *client) Stop() {
	c.pool.Stop()
	c.deferFunc()
}

func (c *client) SetDeferFunc(f func()) {
	c.deferFunc = f
}

func (c *client) IsDone() bool {
	return c.pool.Done
}

func (c *client) GetRunningThreads() int {
	return c.pool.GetRunningThreads()
}

func newClient(config *Config, threads int) *client {
	return &client{
		config:    *config,
		pool:      newPool(threads),
		deferFunc: func() {},
	}
}

type Pool struct {
	Function func(any)
	in       chan any
	threads  int
	Interval time.Duration
	//JobsList *sync.Map
	length int32
	wg     *sync.WaitGroup
	Done   bool
}

const __POOL_SIZE = 64

func newPool(threads int) *Pool {
	return &Pool{
		threads:  threads,
		wg:       &sync.WaitGroup{},
		in:       make(chan any, __POOL_SIZE),
		Interval: time.Duration(0),
		//JobsList: &sync.Map{},
		length: 0,
		Done:   true,
	}
}

func (p *Pool) Run() {
	p.Done = false
	for i := 0; i < p.threads; i++ {
		p.wg.Add(1)
		time.Sleep(p.Interval) //防止线程启动太快
		go p.work()
		if p.Done {
			break
		}
	}
	p.wg.Wait()
}

func (p *Pool) work() {
	defer func() {
		defer func() {
			if e := recover(); e != nil {
				Common.LogError("Pool work error: %s", e.(error).Error())
			}
		}()
		p.wg.Done()
	}()

	for param := range p.in {
		if p.Done {
			return
		}
		atomic.AddInt32(&p.length, 1)
		p.Function(param)
		atomic.AddInt32(&p.length, -1)
	}

}

func (p *Pool) Stop() {
	if p.Done != true {
		close(p.in)
	}
	p.Done = true
}

func (p *Pool) GetThreadsLength() int {
	return p.threads
}

func (p *Pool) GetRunningThreads() int {
	return int(p.length)
}
