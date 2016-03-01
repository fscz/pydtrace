#!/usr/bin/python

import dtrace
import time

a = dtrace.DTraceConsumer()

a.strcompile('dtrace:::BEGIN { printf(" %3s %10s %15s    %15s %8s %6s           %10s       %3s", "CPU", "DELTA(us)", "SOURCE", "DEST", "INT", "BYTES", "EXECUTABLE", "PID"); last = timestamp; } ip:::send { this->delta = (timestamp - last) / 1000; printf(" %3d %10d %15s:%6d -> %15s:%6d %8s %6d %20s   %6d", cpu, this->delta, args[2]->ip_saddr, args[1]->sport, args[2]->ip_daddr, args[1]->dport, args[3]->if_name, args[2]->ip_plength, execname, pid); last = timestamp; }')

a.go()

def walk(probe, record):
  print record


while True:
  time.sleep(1)
  a.consume(walk)
