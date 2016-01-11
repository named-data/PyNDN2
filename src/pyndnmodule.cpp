#include <Python.h>
#include <ndn-cpp/c/errors.h>

extern "C" {
  static PyObject *
  _pyndn_getErrorString(PyObject *self, PyObject *args);
}

static PyObject *
_pyndn_getErrorString(PyObject *self, PyObject *args)
{
  int error;
  const char *result;

  if (!PyArg_ParseTuple(args, "i", &error))
    return NULL;
  result = ndn_getErrorString(error);
  return Py_BuildValue("s", result);
}

extern "C" {
  static PyMethodDef PyndnMethods[] = {
    {"getErrorString",  _pyndn_getErrorString, METH_VARARGS,
     "Convert the error code to its string."},
    {NULL, NULL, 0, NULL} // sentinel
  };

  PyMODINIT_FUNC
  init_pyndn(void)
  {
    (void)Py_InitModule("_pyndn", PyndnMethods);
  }
}
