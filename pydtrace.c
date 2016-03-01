#include <Python.h>
#include <structmember.h>
#include <dtrace.h>

//////////////////////////////////////////////////////////
////////////////////////////////////////////// Definitions 
//////////////////////////////////////////////////////////

typedef struct {
  PyObject_HEAD
  dtrace_hdl_t* dtc_handle;
  PyObject* dtc_callback;
  PyObject* dtc_arguments;
  PyObject* dtc_error;
  dtrace_aggvarid_t dtc_ranges_varid;
  PyObject** dtc_ranges;  
} DTraceConsumer;


//////////////////////////////////////////////////////////
////////////////////////////////////////////// Helpers 
//////////////////////////////////////////////////////////

static unsigned int 
_action_valid(const dtrace_recdesc_t *rec) {

  dtrace_actkind_t action = rec->dtrd_action;

  switch (action) {
  case DTRACEACT_DIFEXPR:
  case DTRACEACT_SYM:
  case DTRACEACT_MOD:
  case DTRACEACT_USYM:
  case DTRACEACT_UMOD:
  case DTRACEACT_UADDR:
    return 1;

  default:
    return 0;
  }
}

static const char * 
_action(const dtrace_recdesc_t *rec, char *buf, int size) {
  static struct {
    dtrace_actkind_t action;
    const char *name;
  } act[] = {
    { DTRACEACT_NONE, "<none>" },
    { DTRACEACT_DIFEXPR,  "<DIF expression>" },
    { DTRACEACT_EXIT, "exit()" },
    { DTRACEACT_PRINTF, "printf()" },
    { DTRACEACT_PRINTA, "printa()" },
    { DTRACEACT_LIBACT, "<library action>" },
    { DTRACEACT_USTACK, "ustack()" },
    { DTRACEACT_JSTACK, "jstack()" },
    { DTRACEACT_USYM, "usym()" },
    { DTRACEACT_UMOD, "umod()" },
    { DTRACEACT_UADDR,  "uaddr()" },
    { DTRACEACT_STOP, "stop()" },
    { DTRACEACT_RAISE,  "raise()" },
    { DTRACEACT_SYSTEM, "system()" },
    { DTRACEACT_FREOPEN,  "freopen()" },
    { DTRACEACT_STACK,  "stack()" },
    { DTRACEACT_SYM,  "sym()" },
    { DTRACEACT_MOD,  "mod()" },
    { DTRACEAGG_COUNT,  "count()" },
    { DTRACEAGG_MIN,  "min()" },
    { DTRACEAGG_MAX,  "max()" },
    { DTRACEAGG_AVG,  "avg()" },
    { DTRACEAGG_SUM,  "sum()" },
    { DTRACEAGG_STDDEV, "stddev()" },
    { DTRACEAGG_QUANTIZE, "quantize()" },
    { DTRACEAGG_LQUANTIZE,  "lquantize()" },
    { DTRACEAGG_LLQUANTIZE, "llquantize()" },
    { DTRACEACT_NONE, NULL },
  };

  dtrace_actkind_t action = rec->dtrd_action;
  int i;

  for (i = 0; act[i].name != NULL; i++) {
    if (act[i].action == action)
      return (act[i].name);
  }

  (void) snprintf(buf, size, "<unknown action 0x%x>", action);

  return (buf);
}

static int
_valid(const dtrace_recdesc_t *rec) {
  dtrace_actkind_t action = rec->dtrd_action;

  switch (action) {
  case DTRACEACT_DIFEXPR:
  case DTRACEACT_SYM:
  case DTRACEACT_MOD:
  case DTRACEACT_USYM:
  case DTRACEACT_UMOD:
  case DTRACEACT_UADDR:
    return (1);

  default:
    return (0);
  }
}

static PyObject* 
_error(const char *fmt, ...) {
  char buf[1024], buf2[1024];
  char *err = buf;

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);

  if (buf[strlen(buf) - 1] != '\n') {
    /*
     * If our error doesn't end in a new-line, we'll append the
     * strerror of errno.
     */
    snprintf(err = buf2, sizeof (buf2),
        "%s: %s", buf, strerror(errno));
  } else {
    buf[strlen(buf) - 1] = '\0';
  }

  return Py_BuildValue("s", err);
}

/*
 * Caching the quantized ranges improves performance substantially if the
 * aggregations have many disjoing keys.  Note that we only cache a single
 * aggregation variable; programs that have more than one aggregation variable
 * may see significant degradations in performance.  (If this is a common
 * case, this cache should clearly be expanded.)
 */
static PyObject**
_ranges_cached(DTraceConsumer *dtc, dtrace_aggvarid_t varid) {
  if (varid == dtc->dtc_ranges_varid) {
    return (dtc->dtc_ranges);
  }

  return NULL;
}

static PyObject**
_ranges_cache(DTraceConsumer *dtc, dtrace_aggvarid_t varid, PyObject** ranges) {
  if (dtc->dtc_ranges != NULL) {
    free(dtc->dtc_ranges);
  }

  dtc->dtc_ranges = ranges;
  dtc->dtc_ranges_varid = varid;

  return (ranges);
}

static PyObject**
_ranges_quantize(DTraceConsumer *dtc, dtrace_aggvarid_t varid) {
  
  PyObject** ranges;
  if ((ranges = _ranges_cached(dtc, varid)) != NULL) {
    return (ranges);
  }  

  ranges = malloc(DTRACE_QUANTIZE_NBUCKETS*sizeof(PyObject*));

  int64_t min, max;
  int i;
  for (i = 0; i < DTRACE_QUANTIZE_NBUCKETS; i++) {
    ranges[i] = PyList_New(2);

    if (i < DTRACE_QUANTIZE_ZEROBUCKET) {
      /*
       * If we're less than the zero bucket, our range
       * extends from negative infinity through to the
       * beginning of our zeroth bucket.
       */
      min = i > 0 ? DTRACE_QUANTIZE_BUCKETVAL(i - 1) + 1 :
          INT64_MIN;
      max = DTRACE_QUANTIZE_BUCKETVAL(i);
    } else if (i == DTRACE_QUANTIZE_ZEROBUCKET) {
      min = max = 0;
    } else {
      min = DTRACE_QUANTIZE_BUCKETVAL(i);
      max = i < DTRACE_QUANTIZE_NBUCKETS - 1 ?
          DTRACE_QUANTIZE_BUCKETVAL(i + 1) - 1 :
          INT64_MAX;
    }

    PyList_SetItem(ranges[i], 0, Py_BuildValue("i", min));
    PyList_SetItem(ranges[i], 1, Py_BuildValue("i", max));
  }

  return (_ranges_cache(dtc, varid, ranges));
}

static PyObject**
_ranges_lquantize(DTraceConsumer *dtc, dtrace_aggvarid_t varid, const uint64_t arg) {
  
  PyObject** ranges;
  if ((ranges = _ranges_cached(dtc, varid)) != NULL)
    return (ranges);

  int64_t min, max;  
  int32_t base;
  uint16_t step, levels;
  int i;

  base = DTRACE_LQUANTIZE_BASE(arg);
  step = DTRACE_LQUANTIZE_STEP(arg);
  levels = DTRACE_LQUANTIZE_LEVELS(arg);

  ranges = malloc((levels + 2) * sizeof(PyObject*));

  for (i = 0; i <= levels + 1; i++) {
    ranges[i] = PyList_New(2);

    min = i == 0 ? INT64_MIN : base + ((i - 1) * step);
    max = i > levels ? INT64_MAX : base + (i * step) - 1;

    PyList_SetItem(ranges[i], 0, Py_BuildValue("i", min));
    PyList_SetItem(ranges[i], 1, Py_BuildValue("i", max));
  }

  return (_ranges_cache(dtc, varid, ranges));
}

static PyObject**
_ranges_llquantize(DTraceConsumer *dtc, dtrace_aggvarid_t varid, const uint64_t arg, int nbuckets) {

  int64_t value = 1, next, step;  
  int bucket = 0, order;
  uint16_t factor, low, high, nsteps;

  PyObject** ranges;
  if ((ranges = _ranges_cached(dtc, varid)) != NULL) {
    return (ranges);
  }

  factor = DTRACE_LLQUANTIZE_FACTOR(arg);
  low = DTRACE_LLQUANTIZE_LOW(arg);
  high = DTRACE_LLQUANTIZE_HIGH(arg);
  nsteps = DTRACE_LLQUANTIZE_NSTEP(arg);

  ranges = malloc(nbuckets * sizeof(PyObject*));

  for (order = 0; order < low; order++)
    value *= factor;

  ranges[bucket] = PyList_New(2);
  PyList_SetItem(ranges[bucket], 0, Py_BuildValue("i", 0));
  PyList_SetItem(ranges[bucket], 1, Py_BuildValue("i", value - 2));
  bucket++;

  next = value * factor;
  step = next > nsteps ? next / nsteps : 1;

  while (order <= high) {
    ranges[bucket] = PyList_New(2);
    PyList_SetItem(ranges[bucket], 0, Py_BuildValue("i", value));
    PyList_SetItem(ranges[bucket], 1, Py_BuildValue("i", value + step - 1));
    bucket++;

    if ((value += step) != next)
      continue;

    next = value * factor;
    step = next > nsteps ? next / nsteps : 1;
    order++;
  }

  ranges[bucket] = PyList_New(2);
  PyList_SetItem(ranges[bucket], 0, Py_BuildValue("i", value));
  PyList_SetItem(ranges[bucket], 1, Py_BuildValue("i", INT64_MAX));

  assert(bucket + 1 == nbuckets);

  return (_ranges_cache(dtc, varid, ranges));
}

static PyObject* 
_make_probedesc(const dtrace_probedesc_t *pd) {
  PyObject *dict = PyDict_New();
  PyDict_SetItemString(dict, "provider", Py_BuildValue("s", pd->dtpd_provider));
  PyDict_SetItemString(dict, "module", Py_BuildValue("s", pd->dtpd_mod));
  PyDict_SetItemString(dict, "function", Py_BuildValue("s", pd->dtpd_func));
  PyDict_SetItemString(dict, "name", Py_BuildValue("s", pd->dtpd_name));

  return dict;
}

static PyObject* 
_make_record(DTraceConsumer* self, const dtrace_recdesc_t *rec, caddr_t addr) {

  switch (rec->dtrd_action) {
  case DTRACEACT_DIFEXPR:
    switch (rec->dtrd_size) {
      case sizeof (uint64_t):
      case sizeof (uint32_t):
      case sizeof (uint16_t):
      case sizeof (uint8_t):
        return Py_BuildValue("l", *(int64_t *)addr);
      default:
        return Py_BuildValue("s", (const char *)addr);
    }
  case DTRACEACT_SYM:
  case DTRACEACT_MOD:
  case DTRACEACT_USYM:
  case DTRACEACT_UMOD:
  case DTRACEACT_UADDR:
    {
      dtrace_hdl_t* dtp = self->dtc_handle;
      char buf[2048], *tick, *plus;

      buf[0] = '\0';

      if (DTRACEACT_CLASS(rec->dtrd_action) == DTRACEACT_KERNEL) {
        uint64_t pc = ((uint64_t *)addr)[0];
        dtrace_addr2str(dtp, pc, buf, sizeof (buf) - 1);
      } else {
        uint64_t pid = ((uint64_t *)addr)[0];
        uint64_t pc = ((uint64_t *)addr)[1];
        dtrace_uaddr2str(dtp, pid, pc, buf, sizeof (buf) - 1);
      }

      if (rec->dtrd_action == DTRACEACT_MOD ||
          rec->dtrd_action == DTRACEACT_UMOD) {
        /*
         * If we're looking for the module name, we'll
         * return everything to the left of the left-most
         * tick -- or "<undefined>" if there is none.
         */
        if ((tick = strchr(buf, '`')) == NULL)
          return Py_BuildValue("s", "<unknown>");

        *tick = '\0';
      } else if (rec->dtrd_action == DTRACEACT_SYM ||
          rec->dtrd_action == DTRACEACT_USYM) {
        /*
         * If we're looking for the symbol name, we'll
         * return everything to the left of the right-most
         * plus sign (if there is one).
         */
        if ((plus = strrchr(buf, '+')) != NULL)
          *plus = '\0';
      }
      return Py_BuildValue("s", buf);
    }
  }

  assert(0);
  return Py_BuildValue("l", -1);
}

static int 
_aggwalk(const dtrace_aggdata_t *agg, void *arg) {

  DTraceConsumer *dtc = (DTraceConsumer *)arg;
  const dtrace_aggdesc_t *aggdesc = agg->dtada_desc;
  const dtrace_recdesc_t *aggrec;


  /*
   * We expect to have both a variable ID and an aggregation value here;
   * if we have fewer than two records, something is deeply wrong.
   */
  assert(aggdesc->dtagd_nrecs >= 2);


  PyObject* keys = PyList_New(aggdesc->dtagd_nrecs - 2);
  PyObject* id = Py_BuildValue("i", aggdesc->dtagd_varid);
  PyObject* val = NULL;

  char errbuf[256];
  int i;


  for (i = 1; i < aggdesc->dtagd_nrecs - 1; i++) {
    const dtrace_recdesc_t *rec = &aggdesc->dtagd_rec[i];
    caddr_t addr = agg->dtada_data + rec->dtrd_offset;    

    if (!_valid(rec)) {
      dtc->dtc_error = _error("unsupported action %s as key #%d in aggregation \"%s\"\n", _action(rec, errbuf, sizeof (errbuf)), i, aggdesc->dtagd_name);
      return (DTRACE_AGGWALK_ERROR);
    }

    PyList_SetItem(keys, i - 1, _make_record(dtc, rec, addr));
  }

  aggrec = &aggdesc->dtagd_rec[aggdesc->dtagd_nrecs - 1];

  switch (aggrec->dtrd_action) {
  case DTRACEAGG_COUNT:
  case DTRACEAGG_MIN:
  case DTRACEAGG_MAX:
  case DTRACEAGG_SUM: {
    caddr_t addr = agg->dtada_data + aggrec->dtrd_offset;

    assert(aggrec->dtrd_size == sizeof (uint64_t));
    val = Py_BuildValue("l", *((int64_t *)addr));
    break;
  }

  case DTRACEAGG_AVG: {
    const int64_t *data = (int64_t *)(agg->dtada_data + aggrec->dtrd_offset);

    assert(aggrec->dtrd_size == sizeof (uint64_t) * 2);

    val = Py_BuildValue("l", data[1] / (double)data[0]);
    break;
  }

  case DTRACEAGG_QUANTIZE: {
    PyObject* quantize = PyList_New(0);

    const int64_t *data = (int64_t *)(agg->dtada_data + aggrec->dtrd_offset);
    
    PyObject* datum;
    PyObject** ranges = _ranges_quantize(dtc, aggdesc->dtagd_varid); 
    int i;
    for (i = 0; i < DTRACE_QUANTIZE_NBUCKETS; i++) {

      if (!data[i]) continue;

      datum = PyList_New(2);
      PyList_SetItem(datum, 0, ranges[i]);
      PyList_SetItem(datum, 1, Py_BuildValue("i", data[i]));

      PyList_Append(quantize, datum);
    }

    val = quantize;
    break;
  }

  case DTRACEAGG_LQUANTIZE:
  case DTRACEAGG_LLQUANTIZE: {

    const int64_t *data = (int64_t *)(agg->dtada_data + aggrec->dtrd_offset);

    PyObject* lquantize = PyList_New(0);
    PyObject** ranges;
    PyObject* datum;

    int i;

    uint64_t arg = *data++;
    int levels = (aggrec->dtrd_size / sizeof (uint64_t)) - 1;

    ranges = (aggrec->dtrd_action == DTRACEAGG_LQUANTIZE ?
        _ranges_lquantize(dtc, aggdesc->dtagd_varid, arg) :
        _ranges_llquantize(dtc, aggdesc->dtagd_varid, arg, levels));

    for (i = 0; i < levels; i++) {

      if (!data[i]) continue;

      datum = PyList_New(2);
      PyList_SetItem(datum, 0, ranges[i]);
      PyList_SetItem(datum, 1, Py_BuildValue("i", data[i]));

      PyList_Append(lquantize, datum);
    }

    val = lquantize;
    break;
  }

  default:
    dtc->dtc_error = _error("unsupported aggregating action %s in aggregation \"%s\"\n", _action(aggrec, errbuf, sizeof (errbuf)), aggdesc->dtagd_name);
    return (DTRACE_AGGWALK_ERROR);
  }

  PyObject_CallFunction(dtc->dtc_callback, "iOO", id, keys, val);

  return (DTRACE_AGGWALK_REMOVE);
}

static int 
_bufhandler(const dtrace_bufdata_t *bufdata, void *arg) {

  dtrace_probedata_t *data = bufdata->dtbda_probe;
  const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;
  DTraceConsumer *dtc = (DTraceConsumer *)arg;

  if (rec == NULL || rec->dtrd_action != DTRACEACT_PRINTF)
    return (DTRACE_HANDLE_OK);


  PyObject* probe = _make_probedesc(data->dtpda_pdesc);
  PyObject* record = Py_BuildValue("s", bufdata->dtbda_buffered);

  PyObject* result = PyObject_CallFunction((PyObject*)dtc->dtc_callback, "OO", probe, record);
  Py_XDECREF(result);

  return (DTRACE_HANDLE_OK);
}

static int 
_consume(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg) {
  DTraceConsumer *dtc = (DTraceConsumer *)arg;
  dtrace_probedesc_t *pd = data->dtpda_pdesc;

  PyObject* probe = _make_probedesc(data->dtpda_pdesc);

  if (rec == NULL) {
    //PyObject* result = PyObject_CallFunction((PyObject*)dtc->dtc_callback, "OO", probe, Py_None);
    //Py_XDECREF(result);

    return (DTRACE_CONSUME_NEXT);

  } else if (!_action_valid(rec)) {

    /*
     * If this is a printf(), we'll defer to the bufhandler.
     */     
    if (rec->dtrd_action == DTRACEACT_PRINTF) {
      return (DTRACE_CONSUME_THIS);
    }


    char errbuf[256];
    dtc->dtc_error = _error("unsupported action %s in record for %s:%s:%s:%s\n",
                              _action(rec, errbuf, sizeof (errbuf)),
                              pd->dtpd_provider, 
                              pd->dtpd_mod,
                              pd->dtpd_func, 
                              pd->dtpd_name); 

    return (DTRACE_CONSUME_ABORT);
  }

  PyObject* record = _make_record(dtc, rec, data->dtpda_data);

  PyObject* result = PyObject_CallFunction((PyObject*)dtc->dtc_callback, "OO", probe, record);  
  Py_XDECREF(result);

  return (DTRACE_CONSUME_NEXT);
}

//////////////////////////////////////////////////////////
///////////////////////////////////////////////////// API 
//////////////////////////////////////////////////////////

static int
DTraceConsumer_init(DTraceConsumer *self, PyObject *args, PyObject *kwds) {  
  if ( self->dtc_handle ) {
    //PyErr_SetString(PyExc_AttributeError, "cannot reinitialize \"DTraceConsumer\"");
    return 0;
  }

  int err;
  dtrace_hdl_t *dtp;

  if ((dtp = self->dtc_handle = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
    PyErr_SetString(PyExc_RuntimeError, dtrace_errmsg(NULL, err));
    return -1;
  }

  /*
   * Set our buffer size and aggregation buffer size to the de facto
   * standard of 4M.
   */
  (void) dtrace_setopt(dtp, "bufsize", "4m");
  (void) dtrace_setopt(dtp, "aggsize", "4m");


  
  if (dtrace_handle_buffered(dtp, _bufhandler, self) == -1) {
    PyErr_SetString(PyExc_AttributeError, dtrace_errmsg(dtp, dtrace_errno(dtp)));
  }
  

  self->dtc_ranges = NULL;

  // ignore arguments

  return 0;
}

static void
DTraceConsumer_dealloc(DTraceConsumer* self) {
  if ( self->dtc_handle ) {
    dtrace_close( self->dtc_handle );
  }  
  
  self->ob_type->tp_free((PyObject*)self);
}

static PyObject* 
DTraceConsumer_strcompile(DTraceConsumer* self, PyObject *args, PyObject *kwds) {

  static char *kwlist[] = {"program", NULL};
  char* program = NULL;
  
  if ( !PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &program) ) {
    PyErr_SetString(PyExc_AttributeError, "strcompile accepts a python string as argument.");
    return NULL;
  } 

  dtrace_hdl_t *dtp = self->dtc_handle;
  dtrace_prog_t *dp;
  dtrace_proginfo_t info;

  if ((dp = dtrace_program_strcompile(dtp, program, DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
    PyErr_SetObject(PyExc_AttributeError, _error("couldn't compile '%s': %s\n", program, dtrace_errmsg(dtp, dtrace_errno(dtp))));
    return NULL;
  }

  if (dtrace_program_exec(dtp, dp, &info) == -1) {
    PyErr_SetObject(PyExc_AttributeError, _error("couldn't execute '%s': %s\n", program, dtrace_errmsg(dtp, dtrace_errno(dtp))));
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* 
DTraceConsumer_setopt(DTraceConsumer* self, PyObject *args, PyObject *kwds) {
  printf("setopt\n");
  Py_RETURN_NONE;
}

static PyObject* 
DTraceConsumer_go(DTraceConsumer* self, PyObject *args, PyObject *kwds) {
  if (dtrace_go(self->dtc_handle) == -1) {
    PyErr_SetObject(PyExc_AttributeError, _error("couldn't enable tracing: %s\n", dtrace_errmsg(self->dtc_handle, dtrace_errno(self->dtc_handle))));
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* 
DTraceConsumer_consume(DTraceConsumer* self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"callback", NULL};
  PyObject* pyCallback = NULL;
  
  if ( !PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &pyCallback) ) {
    PyErr_SetString(PyExc_AttributeError, "Invalid parameters: consume accepts a callback function and a nullable array of objects that act as additional arguments to the callback as inputs");
    return NULL;
  }  

  dtrace_workstatus_t status;


  self->dtc_callback = pyCallback;
  self->dtc_error = Py_None;

  status = dtrace_work(self->dtc_handle, NULL, NULL, _consume, self);

  if (status == -1 && self->dtc_error != Py_None) {
    PyErr_SetObject(PyExc_RuntimeError, self->dtc_error);
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* 
DTraceConsumer_aggwalk(DTraceConsumer* self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"callback", NULL};
  PyObject* pyCallback = NULL;
  
  if ( !PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &pyCallback) ) {
    PyErr_SetString(PyExc_AttributeError, "Invalid parameters: consume accepts a callback function and a nullable array of objects that act as additional arguments to the callback as inputs");
    return NULL;
  }  


  dtrace_hdl_t *dtp = self->dtc_handle;
  int rval;

  self->dtc_callback = pyCallback;
  self->dtc_error = Py_None;

  if (dtrace_status(dtp) == -1) {
    PyErr_SetObject(PyExc_RuntimeError, _error("couldn't get status: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp))));
    return NULL;
  }

  if (dtrace_aggregate_snap(dtp) == -1) {
    PyErr_SetObject(PyExc_RuntimeError, _error("couldn't snap aggregate: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp))));
    return NULL;
  }

  rval = dtrace_aggregate_walk(dtp, _aggwalk, self);

  /*
   * Flush the ranges cache; the ranges will go out of scope when the
   * destructor for our HandleScope is called, and we cannot be left
   * holding references.
   */
  _ranges_cache(self, DTRACE_AGGVARIDNONE, NULL);

  if (rval == -1) {

    if (self->dtc_error != Py_None) {
      PyErr_SetObject(PyExc_RuntimeError, self->dtc_error);
      return NULL;
    } else {
      PyErr_SetObject(PyExc_RuntimeError, _error("couldn't walk aggregate: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp))));
      return NULL;
    }
  }

  Py_RETURN_NONE;
}

static PyObject* 
DTraceConsumer_aggclear(DTraceConsumer* self, PyObject *args, PyObject *kwds) {

  dtrace_hdl_t *dtp = self->dtc_handle;

  if (dtrace_status(dtp) == -1) {
    PyErr_SetObject(PyExc_RuntimeError, _error("couldn't get status: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp))));
    return NULL;
  }

  dtrace_aggregate_clear(dtp);

  Py_RETURN_NONE;
}

static PyObject* 
DTraceConsumer_aggmin(DTraceConsumer* self, PyObject *args, PyObject *kwds) {
  return Py_BuildValue("l", INT64_MIN);
}

static PyObject* 
DTraceConsumer_aggmax(DTraceConsumer* self, PyObject *args, PyObject *kwds) {
  return Py_BuildValue("l", INT64_MAX);
}

static PyObject* 
DTraceConsumer_stop(DTraceConsumer* self, PyObject *args, PyObject *kwds) {

  dtrace_hdl_t *dtp = self->dtc_handle;
  
  if (dtrace_stop(dtp) == -1) { 
    PyErr_SetObject(PyExc_RuntimeError, _error("couldn't disable tracing: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp))));
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject* 
DTraceConsumer_version(DTraceConsumer* self, PyObject *args, PyObject *kwds) {
  return Py_BuildValue("s", _dtrace_version);
}

static PyMemberDef DTraceConsumer_members[] = {
  //{"handle", T_INT, offsetof(DTraceConsumer, dtc_handle), 0, "libdtrace state token"},
  {NULL}  /* Sentinel */
};

static PyMethodDef DTraceConsumer_methods[] = {
  {"strcompile", (PyCFunction)DTraceConsumer_strcompile, METH_VARARGS, "compile the supplied d-program" },
  {"setopt", (PyCFunction)DTraceConsumer_setopt, METH_VARARGS, "set libdtrace options" },
  {"go", (PyCFunction)DTraceConsumer_go, METH_VARARGS, "execute the compiled d-program" },
  {"consume", (PyCFunction)DTraceConsumer_consume, METH_VARARGS, "consume outputs of the running d-program" },
  {"aggwalk", (PyCFunction)DTraceConsumer_aggwalk, METH_VARARGS, "consume outputs for all aggregations of the running d-program" },
  {"aggclear", (PyCFunction)DTraceConsumer_aggclear, METH_VARARGS, "clear outputs for all aggregations of the running d-program" },
  {"aggmin", (PyCFunction)DTraceConsumer_aggmin, METH_VARARGS, "minimum int64 value" },
  {"aggmax", (PyCFunction)DTraceConsumer_aggmax, METH_VARARGS, "maximum int64 value" },
  {"stop", (PyCFunction)DTraceConsumer_stop, METH_VARARGS, "stop execution of the running d-program" },
  {"version", (PyCFunction)DTraceConsumer_version, METH_VARARGS, "return the version string of libdtrace" },
  {NULL}  /* Sentinel */
};

static PyTypeObject DTraceConsumerType = {
  PyObject_HEAD_INIT(NULL)
  0,                         /*ob_size*/
  "libdtrace.DTraceConsumer",             /*tp_name*/
  sizeof(DTraceConsumer),             /*tp_basicsize*/
  0,                         /*tp_itemsize*/
  (destructor)DTraceConsumer_dealloc, /*tp_dealloc*/
  0,                         /*tp_print*/
  0,                         /*tp_getattr*/
  0,                         /*tp_setattr*/
  0,                         /*tp_compare*/
  0,                         /*tp_repr*/
  0,                         /*tp_as_number*/
  0,                         /*tp_as_sequence*/
  0,                         /*tp_as_mapping*/
  0,                         /*tp_hash */
  0,                         /*tp_call*/
  0,                         /*tp_str*/
  0,                         /*tp_getattro*/
  0,                         /*tp_setattro*/
  0,                         /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "DTrace binding object",           /* tp_doc */
  0,                     /* tp_traverse */
  0,                     /* tp_clear */
  0,                     /* tp_richcompare */
  0,                     /* tp_weaklistoffset */
  0,                     /* tp_iter */
  0,                     /* tp_iternext */
  DTraceConsumer_methods,             /* tp_methods */
  DTraceConsumer_members,             /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  (initproc)DTraceConsumer_init,      /* tp_init */
  0,                         /* tp_alloc */
  PyType_GenericNew,                 /* tp_new */
};


//////////////////////////////////////////////////////////
///////////////////////////// Module
//////////////////////////////////////////////////////////

static PyMethodDef module_methods[] = {
  {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initdtrace(void)
{
  PyObject* m;

  if ( PyType_Ready(&DTraceConsumerType) < 0 ) {
    return;
  } 

  m = Py_InitModule3("dtrace", module_methods, "python binding to libdtrace");

  
  if (m == NULL) {
    return;
  }

  Py_INCREF(&DTraceConsumerType);
  PyModule_AddObject(m, "DTraceConsumer", (PyObject *)&DTraceConsumerType);
}