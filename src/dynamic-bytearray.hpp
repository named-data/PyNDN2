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

#ifndef NDN_DYNAMIC_BYTEARRAY_HPP
#define NDN_DYNAMIC_BYTEARRAY_HPP

#include <Python.h>
#include <ndn-cpp/lite/util/dynamic-uint8-array-lite.hpp>
#include "py-object-ref.hpp"

/**
 * A DynamicBytearray extends DynamicUInt8ArrayLite to hold a Python bytearray
 * object and provide a realloc function for use with C functions which need an
 * ndn_DynamicUInt8Array.
 */
class DynamicBytearray : public ndn::DynamicUInt8ArrayLite {
public:
  DynamicBytearray(size_t initialLength)
  : ndn::DynamicUInt8ArrayLite(0, 0, (ndn_ReallocFunction)&DynamicBytearray::realloc),
    bytearray_(PyByteArray_FromStringAndSize("", 0))
  {
    // Now that bytearray_ is constructed, we can set array in the base class.
    setArrayAndLength(realloc
      (this, (uint8_t*)PyByteArray_AS_STRING(bytearray_.obj), initialLength),
      initialLength);
  }

  /**
   * Resize the bytearray to the given size, and return the bytearray object.
   * @param size The final size of the allocated vector.
   * @return The Python bytearray object.
   */
  PyObject*
  finish(size_t size)
  {
    PyByteArray_Resize(bytearray_.obj, size);
    return bytearray_.obj;
  }

private:
  /**
   * Implement the static realloc function using PyByteArray_Resize.
   * @param self A pointer to this object.
   * @param array Should be PyByteArray_AS_STRING(bytearray_).
   * @param length The new length for the vector.
   * @return The new PyByteArray_AS_STRING(bytearray_) or 0 if can't resize.
   */
  static uint8_t*
  realloc(DynamicBytearray *self, uint8_t *array, size_t length)
  {
    if ((char*)array != PyByteArray_AS_STRING(self->bytearray_.obj))
      // We don't expect this to ever happen. The caller didn't pass the array
      // from this object.
      return 0;

    if (PyByteArray_Resize(self->bytearray_.obj, length) != 0)
      return 0;
    return (uint8_t*)PyByteArray_AS_STRING(self->bytearray_.obj);
  }

  PyObjectRef bytearray_;
};

#endif
