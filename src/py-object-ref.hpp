/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

#ifndef NDN_PY_OBJECT_REF_HPP
#define NDN_PY_OBJECT_REF_HPP

#include <Python.h>

/**
 * When PyObjectRef goes out of scope, it calls Py_DECREF on the PyObject given
 * to the constructor.
 */
class PyObjectRef {
public:
  PyObjectRef()
  : obj(0)
  {}

  PyObjectRef(PyObject* obj)
  : obj(obj)
  {}

  ~PyObjectRef()
  {
    if (obj)
      Py_DECREF(obj);
  }

  void
  reset(PyObject* obj)
  {
    if (this->obj)
      Py_DECREF(this->obj);
    this->obj = obj;
  }

  operator PyObject*() { return obj; }

  PyObject* obj;

private:
  // Don't allow copying.
  PyObjectRef(const PyObjectRef& other);
  PyObjectRef& operator=(const PyObjectRef& other);
};

#endif
