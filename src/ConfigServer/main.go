package configserver

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Config struct {
	Listen   string
	RootPath string
}

type value struct {
	ctx    context.Context
	cf     context.CancelFunc
	mutex  sync.Mutex
	status int
	value  string
	hash   string
}

func (s *value) load(path string) error {
	log.Printf("Load file from %s", path)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.status = http.StatusNotFound
	if data, err := os.ReadFile(path); err != nil {
		log.Printf("Load file from %s failed, %s.", path, err)
		return err
	} else {
		hash := md5.Sum([]byte(data))
		s.value = string(data)
		s.hash = hex.EncodeToString(hash[:])
		s.status = http.StatusAccepted
	}
	if s.cf != nil {
		s.cf()
	}
	s.ctx, s.cf = context.WithCancel(context.Background())
	return nil
}

type Web struct {
	Config
	echo      *echo.Echo
	watch     map[string]*value
	mutex     sync.Mutex
	fswatcher *fsnotify.Watcher
}

func (s *Web) Run() {
	var err error
	s.echo = echo.New()
	if s.fswatcher, err = fsnotify.NewWatcher(); err != nil {
		log.Fatal(err)
	}
	if s.RootPath, err = filepath.Abs(s.RootPath); err != nil {
		log.Fatal(err)
	}
	s.watch = make(map[string]*value)
	s.echo.GET("/*", s.Get)
	s.echo.Use(middleware.Logger())
	go s.fsWatch()
	log.Fatal(s.echo.Start(s.Listen))
}

func (s *Web) fsRemove(name string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.fswatcher.Remove(name)
	if v, ok := s.watch[name]; ok {
		v.cf()
		delete(s.watch, name)
	}
}

func (s *Web) fsWatch() {
	for {
		select {
		case event, ok := <-s.fswatcher.Events:
			if !ok {
				log.Fatal("fsWatch failed.")
			}
			switch event.Op {
			case fsnotify.Write:
				if v, ok := s.watch[event.Name]; ok {
					//reload data file.
					if err := v.load(event.Name); err != nil {
						s.fsRemove(event.Name)
					}
				} else {
					s.fswatcher.Remove(event.Name)
				}
			case fsnotify.Remove:
				s.fsRemove(event.Name)
			case fsnotify.Rename:
				s.fsRemove(event.Name)
			}
		case err, ok := <-s.fswatcher.Errors:
			if !ok {
				log.Fatal("fsWatch failed.")
			}
			log.Println("error:", err)
		}
	}
}

func (s *Web) realPath(path string) string {
	requestPath := fmt.Sprintf("%s%s", s.RootPath, path)
	realPath, err := filepath.Abs(requestPath)
	if err != nil || !strings.HasPrefix(realPath, s.RootPath) {
		return ""
	}
	return realPath
}

func (s *Web) Get(c echo.Context) error {
	path := s.realPath(c.Request().URL.Path)
	if path == "" {
		return echo.ErrNotFound
	}
	//load hash from URI
	hash := c.Request().URL.Query().Get("hash")
	//load hash from header
	if hash == "" {
		if v, ok := c.Request().Header["Hash"]; ok && len(v) >= 0 {
			hash = v[0]
		}
	}
	if v, ok := s.watch[path]; ok {
		if v.hash == hash {
			select {
			case <-v.ctx.Done():
				c.Response().Header().Set("hash", v.hash)
				if v.status == http.StatusAccepted {
					c.String(http.StatusOK, v.value)
				} else {
					return echo.ErrNotFound
				}
			case <-time.After(1 * time.Hour):
				c.Response().WriteHeader(http.StatusNoContent)
			}
		} else {
			c.Response().Header().Set("hash", v.hash)
			c.String(http.StatusOK, v.value)
		}
	} else {
		v := value{}
		if err := v.load(path); err != nil {
			return echo.ErrNotFound
		}
		s.mutex.Lock()
		s.watch[path] = &v
		s.mutex.Unlock()
		s.fswatcher.Add(path)
		c.Response().Header().Set("hash", v.hash)
		c.String(http.StatusOK, v.value)
	}
	return nil
}
