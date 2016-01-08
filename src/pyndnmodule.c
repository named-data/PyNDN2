#include <Python.h>

static PyObject *
_pyndn_system(PyObject *self, PyObject *args)
{
    const char *command;
    int sts;

    if (!PyArg_ParseTuple(args, "s", &command))
        return NULL;
    sts = system(command);
    return Py_BuildValue("i", sts);
}

static PyMethodDef PyndnMethods[] = {
    {"system",  _pyndn_system, METH_VARARGS,
     "Execute a shell command."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
init_pyndn(void)
{
    (void) Py_InitModule("_pyndn", PyndnMethods);
}
