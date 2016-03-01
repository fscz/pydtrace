# pydtrace
python binding to libdtrace

Overview
---
This is a python extension that acts as a binding to libdtrace. The code at the moment
is a straightforward port from node-libdtrace (https://github.com/bcantrill/node-libdtrace).
Many thanks to Bryan Cantrill for his work, it made this effort a lot easier.

There have been other attempts at creating a python binding to libdtrace, most notably
http://tmetsch.github.io/python-dtrace/. However I have never been a fan of ctypes and
think that Cython is outright disgusting. Moreover I could not get "python-dtrace" to 
work on OSX.

pydtrace should work on any Unix/BSD with dtrace and OSX 10.5+. If it does not, let me know.


Building
---
- git clone https://github.com/fscz/pydtrace.git
- cd pydtrace
- make

This will build an so-file dtrace.so that you can directly import in a python script, using "import dtrace"
 


API
---

### `dtrace.DTraceConsumer()`

Create a new DTraceConsumer, which will correspond to a new `libdtrace`
state.  If DTrace cannot be initalized for any reason, this will throw an
exception with the `message` member set to the more detailed reason from
libdtrace.  Note that one particularly common failure mode is attempting to
initialize DTrace without the necessary level of privilege; in this case, for
example, the `message` member will be:

      DTrace requires additional privileges

(The specifics of this particular message should obviously not be 
programmatically depended upon.)  If encountering this error, you will
need to be a user that has DTrace privileges.

### `consumer.strcompile(str)`

Compile the specified `str` as a D program.  This is required before
any call to `consumer.go()`.

### `consumer.go()`

Instruments the system using the specified enabling.  Before `consumer.go()`
is called, the specified D program has been compiled but not executed; once
`consumer.go()` is called, no further D compilation is possible.

### `consumer.setopt(option, value)`

Sets the specified `option` (a string) to `value` (an integer, boolean,
string, or string representation of an integer or boolean, as denoted by
the option being set).

### `consumer.consume(callback :: probe, rec -> None)`

Consume any DTrace data traced to the principal buffer since the last call to
`consumer.consume()` (or the call to `consumer.go()` if `consumer.consume()`
has not been called).  For each trace record, `func` will be called and
passed two arguments:

* `probe` is a python dict that specifies the probe that corresponds to the
   trace record in terms of the probe tuple: provider, module, function
   and name.

* `rec` is a string that corresponds to the datum within the trace record. If the record has been fully
   consumed, `rec` will be `None`.

In terms of implementation, a call to `consumer.consume()` will result in a
call to `dtrace_status()` and a principal buffer switch.  Note that if the
rate of consumption exceeds the specified `switchrate` (set via either
`#pragma D option switchrate` or `consumer.setopt()`), this will result in no
new data processing.

### `consumer.aggwalk(callback :: varid, key, value -> None)`

Snapshot and iterate over all aggregation data accumulated since the
last call to `consumer.aggwalk()` (or the call to `consumer.go()` if
`consumer.aggwalk()` has not been called).  For each aggregate record,
`func` will be called and passed three arguments:

* `varid` is the identifier of the aggregation variable.  These IDs are
  assigned in program order, starting with 1.

* `key` is an array of keys that, taken with the variable identifier,
  uniquely specifies the aggregation record.

* `value` is the value of the aggregation record, the meaning of which
  depends on the aggregating action:

  * For `count()`, `sum()`, `max()` and `min()`, the value is the
    integer value of the aggregation action

  * For `avg()`, the value is the numeric value of the aggregating action

  * For `quantize()` and `lquantize()`, the value is an array of 2-tuples
    denoting ranges and value:  each element consists of a two element array
    denoting the range (minimum followed by maximum, inclusive) and the
    value for that range.  

Upon return from `consumer.aggwalk()`, the aggregation data for the specified
variable and key(s) is removed.

Note that the rate of `consumer.aggwalk()` actually consumes the aggregation
buffer is clamed by the `aggrate` option; if `consumer.aggwalk()` is called
more frequently than the specified rate, `consumer.aggwalk()` will not
induce any additional data processing.

`consumer.aggwalk()` does not iterate over aggregation data in any guaranteed
order, and may interleave aggregation variables and/or keys.

### `consumer.version()`

Returns the version string, as returned from `dtrace -V`.

Examples
--------
### Packages being sent over ip
      

      import dtrace
      import time

      c = dtrace.DTraceConsumer()

      c.strcompile('dtrace:::BEGIN { printf(" %3s %10s %15s    %15s %8s %6s           %10s       %3s", "CPU", "DELTA(us)", "SOURCE", "DEST", "INT", "BYTES", "EXECUTABLE", "PID"); last = timestamp; } ip:::send { this->delta = (timestamp - last) / 1000; printf(" %3d %10d %15s:%6d -> %15s:%6d %8s %6d %20s   %6d", cpu, this->delta, args[2]->ip_saddr, args[1]->sport, args[2]->ip_daddr, args[1]->dport, args[3]->if_name, args[2]->ip_plength, execname, pid); last = timestamp; }')

      c.go()

      def walk(probe, record):
        print record


      while True:
        time.sleep(1)
        c.consume(walk)


Learning DTrace
---
If you want to learn more about DTrace check out the following sources
- http://www.brendangregg.com/dtrace.html#OneLiners
- http://www.brendangregg.com/dtracetoolkit.html
- http://dtrace.org/guide/preface.html
