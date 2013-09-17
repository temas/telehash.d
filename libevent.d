import std.socket;
import std.stdio;

enum LoopRun {
  EvLoopOnce = 0x01,
  EvLoopNonBlock = 0x02,
  EvLoopNoExitOnEmpty = 0x04
}

enum EventFlags : short {
  EvTimeout = 0x01,
  EvRead = 0x02,
  EvWrite = 0x04,
  EvSignal = 0x08,
  EvPersist = 0x10,
  EvEt = 0x20
}

alias void delegate(EvLoop*, EventFlags) EventCallback;

/// The wrapper for the event base
struct ev_base;
struct event;

alias extern (C) void function(socket_t, short, void*) EvCallback;
extern (C) event* event_new(ev_base* base, socket_t socket, EventFlags flags, EvCallback, void* arg);
extern (C) ev_base* event_base_new();
extern (C) void event_base_free(ev_base*);
extern (C) int event_base_dispatch(ev_base*);
extern (C) int event_add(event*, void*);

class EvLoop {
  ev_base* base;

  this() {
    base = event_base_new();
  }

  ~this() {
    event_base_free(base);
  }

  /// Keeps dispatching until there is a break or a  scheduled exit
  void dispatch() {
    event_base_dispatch(base);
  }

  /// Schedule a break for the loop
  void scheduleExit(uint timeval) {
  }

  /// Break the loop now
  void breakNow() {
    //event_base_loopbreak(base);
  }

  void addEvent(socket_t socket, EventFlags flags, lazy EventCallback cb) {
    EventWrapper* wrapper = new EventWrapper;
    wrapper.loop = &this;
    wrapper.cb = cb;
    event* event = event_new(base, socket, flags, &handleEvent, wrapper);
    event_add(event, null);
  }
}

struct EventWrapper {
  EvLoop* loop;
  EventCallback cb;
};

extern (C) void handleEvent(socket_t socket, short flags, void* arg) {
  EventWrapper* wrapper = cast(EventWrapper*)arg;
  wrapper.cb(wrapper.loop, cast(EventFlags)flags);
}


