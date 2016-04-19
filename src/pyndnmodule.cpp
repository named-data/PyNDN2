#include <Python.h>
#include <ndn-cpp/lite/encoding/tlv-0_1_1-wire-format-lite.hpp>

using namespace ndn;

/**
 * When PyObjectRef goes out of scope, it calls Py_DECREF on the PyObject given
 * to the constructor.
 */
class PyObjectRef {
public:
  PyObjectRef(PyObject* obj) : obj(obj) {}
  ~PyObjectRef() { if (obj) Py_DECREF(obj); }
  operator PyObject*() { return obj; }
  PyObject* obj;
};

// Static Python string objects.
class strClass {
public:
  strClass() {
    _array = Py_BuildValue("s", "_array");
    _components = Py_BuildValue("s", "_components");
    _view = Py_BuildValue("s", "_view");
    Blob = Py_BuildValue("s", "Blob");
    Sha256WithRsaSignature = Py_BuildValue("s", "Sha256WithRsaSignature");
    append = Py_BuildValue("s", "append");
    clear = Py_BuildValue("s", "clear");
    getContent = Py_BuildValue("s", "getContent");
    getFinalBlockId = Py_BuildValue("s", "getFinalBlockId");
    getFreshnessPeriod = Py_BuildValue("s", "getFreshnessPeriod");
    getKeyData = Py_BuildValue("s", "getKeyData");
    getKeyLocator = Py_BuildValue("s", "getKeyLocator");
    getKeyName = Py_BuildValue("s", "getKeyName");
    getMetaInfo = Py_BuildValue("s", "getMetaInfo");
    getName = Py_BuildValue("s", "getName");
    getValue = Py_BuildValue("s", "getValue");
    getSignature = Py_BuildValue("s", "getSignature");
    getType = Py_BuildValue("s", "getType");
    setContent = Py_BuildValue("s", "setContent");
    setFinalBlockId = Py_BuildValue("s", "setFinalBlockId");
    setFreshnessPeriod = Py_BuildValue("s", "setFreshnessPeriod");
    setKeyData = Py_BuildValue("s", "setKeyData");
    setSignature = Py_BuildValue("s", "setSignature");
    setType = Py_BuildValue("s", "setType");
  }
  PyObject* _array;
  PyObject* _components;
  PyObject* _view;
  PyObject* Blob;
  PyObject* Sha256WithRsaSignature;
  PyObject* append;
  PyObject* clear;
  PyObject* getContent;
  PyObject* getFinalBlockId;
  PyObject* getFreshnessPeriod;
  PyObject* getKeyData;
  PyObject* getKeyLocator;
  PyObject* getKeyName;
  PyObject* getMetaInfo;
  PyObject* getName;
  PyObject* getValue;
  PyObject* getSignature;
  PyObject* getType;
  PyObject* setContent;
  PyObject* setFinalBlockId;
  PyObject* setFreshnessPeriod;
  PyObject* setKeyData;
  PyObject* setSignature;
  PyObject* setType;
};

static strClass str;

static long
toLongByMethod(PyObject* obj, PyObject* methodName)
{
  PyObjectRef val(PyObject_CallMethodObjArgs(obj, methodName, NULL));
  return PyInt_AsLong(val);
}

static double
toDoubleByMethod(PyObject* obj, PyObject* methodName)
{
  PyObjectRef val(PyObject_CallMethodObjArgs(obj, methodName, NULL));
  return PyFloat_AsDouble(val);
}

/**
 * Imitate Blob.toBuffer to get the array in a BlobLite.
 * @param array The array object such as from blob.buf().
 * @return A BlobLite which points into the raw bytes.
 */
static BlobLite
toBlobLiteFromArray(PyObject* array)
{
  // Imitate Blob.toBuffer to be bufferObj.
  PyObject* bufferObj;
  PyObjectRef blobArrayView(0);
  if (PyObject_HasAttr(array, str._view)) {
    // Assume array is a _memoryviewWrapper.
    blobArrayView.obj = PyObject_GetAttr(array, str._view);
    bufferObj = blobArrayView.obj;
  }
  else
    bufferObj = array;

  Py_buffer bufferView;
  if (PyObject_GetBuffer(bufferObj, &bufferView, PyBUF_SIMPLE) != 0)
    // Error. Don't expect this to happen, so just return an empty blob.
    return BlobLite();
  // TODO: Check if it is a byte buffer?
  uint8_t* buf = (uint8_t*)bufferView.buf;
  size_t size = bufferView.len;
  // TODO: Do we have to put this in a pool to be freed later?
  PyBuffer_Release(&bufferView);

  return BlobLite(buf, size);
}

/**
 * Get a Blob by calling obj.methodName() and imitate Blob.toBuffer to get
 * the array in a BlobLite.
 * @param obj The object with the Blob.
 * @param methodName The method name that returns a Blob.
 * @return A BlobLite which points into the raw bytes, or an empty BlobLite if
 * if the Blob isNull.
 */
static BlobLite
toBlobLiteByMethod(PyObject* obj, PyObject* methodName)
{
  PyObjectRef blob(PyObject_CallMethodObjArgs(obj, methodName, NULL));
  PyObjectRef blobArray(PyObject_GetAttr(blob, str._array));
  if (blobArray.obj == Py_None)
    return BlobLite();

  return toBlobLiteFromArray(blobArray);
}

/**
 * Make a new Blob object.
 * @param blobLite The BlobLite with the bytes for the blob, which are copied.
 * @return A new PyObject for the Blob object.
 */
static PyObject*
makeBlob(const BlobLite& blobLite)
{
  PyObjectRef util(PyImport_ImportModule("pyndn.util"));
  PyObjectRef Blob(PyObject_GetAttr(util, str.Blob));
  // TODO: Will this raw string work in Python 3?
  PyObjectRef array(PyByteArray_FromStringAndSize
    ((const char*)blobLite.buf(), (Py_ssize_t)blobLite.size()));

  // Call Blob(array, 0). Use 0 in place of False.
  PyObjectRef args(Py_BuildValue("(O,i)", array.obj, 0));
  return PyObject_CallObject(Blob, args);
}

// Imitate Name::get(NameLite& nameLite).
static void
toNameLite(PyObject* name, NameLite& nameLite)
{
  nameLite.clear();
  PyObjectRef components(PyObject_GetAttr(name, str._components));
  for (size_t i = 0; i < PyList_GET_SIZE(components.obj); ++i) {
    ndn_Error error;
    if ((error = nameLite.append
         (toBlobLiteByMethod
          (PyList_GET_ITEM(components.obj, i), str.getValue))))
      // TODO: Handle the error!
      return;
  }
}

// Imitate Name::set(const NameLite& nameLite).
static void
setName(PyObject* name, const NameLite& nameLite)
{
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs(name, str.clear, NULL));

  for (size_t i = 0; i < nameLite.size(); ++i) {
    PyObjectRef blob(makeBlob(nameLite.get(i).getValue()));
    PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
      (name, str.append, blob.obj, NULL));
  }
}

// Imitate KeyLocator::get(KeyLocatorLite& keyLocatorLite).
static void
toKeyLocatorLite(PyObject* keyLocator, KeyLocatorLite& keyLocatorLite)
{
  keyLocatorLite.setType
    ((ndn_KeyLocatorType)(int)toLongByMethod(keyLocator, str.getType));
  keyLocatorLite.setKeyData
    (toBlobLiteByMethod(keyLocator, str.getKeyData));

  PyObjectRef keyName(PyObject_CallMethodObjArgs
    (keyLocator, str.getKeyName, NULL));
  toNameLite(keyName, keyLocatorLite.getKeyName());
}

// Imitate KeyLocator::set(const KeyLocatorLite& keyLocatorLite).
static void
setKeyLocator(PyObject* keyLocator, const KeyLocatorLite& keyLocatorLite)
{
  PyObjectRef type(PyLong_FromLong(keyLocatorLite.getType()));
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs
    (keyLocator, str.setType, type.obj, NULL));

  PyObjectRef keyData(makeBlob(keyLocatorLite.getKeyData()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (keyLocator, str.setKeyData, keyData.obj, NULL));

  PyObjectRef keyName(PyObject_CallMethodObjArgs(keyLocator, str.getKeyName, NULL));
  if (keyLocatorLite.getType() == ndn_KeyLocatorType_KEYNAME)
    setName(keyName, keyLocatorLite.getKeyName());
  else
    PyObjectRef ignoreResult3(PyObject_CallMethodObjArgs(keyName, str.clear, NULL));
}

// Imitate Sha256WithRsaSignature::get(SignatureLite& signatureLite).
static void
toSha256WithRsaSignatureLite(PyObject* signature, SignatureLite& signatureLite)
{
  signatureLite.setType(ndn_SignatureType_Sha256WithRsaSignature);
  signatureLite.setSignature(toBlobLiteByMethod(signature, str.getSignature));

  PyObjectRef keyLocator
    (PyObject_CallMethodObjArgs(signature, str.getKeyLocator, NULL));
  toKeyLocatorLite(keyLocator, signatureLite.getKeyLocator());
}

// Imitate Sha256WithRsaSignature::set(const SignatureLite& signatureLite).
static void
setSha256WithRsaSignature(PyObject* signature, const SignatureLite& signatureLite)
{
  // The caller should already have checked the type, but check again.
  if (signatureLite.getType() != ndn_SignatureType_Sha256WithRsaSignature)
    return;

  PyObjectRef signatureBlob(makeBlob(signatureLite.getSignature()));
  PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
    (signature, str.setSignature, signatureBlob.obj, NULL));

  PyObjectRef keyLocator(PyObject_CallMethodObjArgs
    (signature, str.getKeyLocator, NULL));
  setKeyLocator(keyLocator, signatureLite.getKeyLocator());
}

// Imitate MetaInfo::get(MetaInfoLite& metaInfoLite).
static void
toMetaInfoLite(PyObject* metaInfo, MetaInfoLite& metaInfoLite)
{
  metaInfoLite.setType((ndn_ContentType)(int)toLongByMethod(metaInfo, str.getType));
  metaInfoLite.setFreshnessPeriod(toDoubleByMethod(metaInfo, str.getFreshnessPeriod));
  PyObjectRef finalBlockId(PyObject_CallMethodObjArgs
    (metaInfo, str.getFinalBlockId, NULL));
  metaInfoLite.setFinalBlockId(NameLite::Component
    (toBlobLiteByMethod(finalBlockId, str.getValue)));
}

// Imitate MetaInfo::set(const MetaInfoLite& metaInfoLite).
static void
setMetaInfo(PyObject* metaInfo, const MetaInfoLite& metaInfoLite)
{
  PyObjectRef type(PyLong_FromLong(metaInfoLite.getType()));
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs
    (metaInfo, str.setType, type.obj, NULL));

  PyObjectRef freshnessPeriod(PyFloat_FromDouble(metaInfoLite.getFreshnessPeriod()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (metaInfo, str.setFreshnessPeriod, freshnessPeriod.obj, NULL));

  PyObjectRef finalBlockId(makeBlob(metaInfoLite.getFinalBlockId().getValue()));
  PyObjectRef ignoreResult3(PyObject_CallMethodObjArgs
    (metaInfo, str.setFinalBlockId, finalBlockId.obj, NULL));
}

// Imitate Data::get(DataLite& dataLite).
static void
toDataLite(PyObject* data, DataLite& dataLite)
{
  // TODO: Handle types other than Sha256WithRsaSignature.
  PyObjectRef signature(PyObject_CallMethodObjArgs(data, str.getSignature, NULL));
  toSha256WithRsaSignatureLite(signature, dataLite.getSignature());

  PyObjectRef name(PyObject_CallMethodObjArgs(data, str.getName, NULL));
  toNameLite(name, dataLite.getName());

  PyObjectRef metaInfo(PyObject_CallMethodObjArgs(data, str.getMetaInfo, NULL));
  toMetaInfoLite(metaInfo, dataLite.getMetaInfo());

  dataLite.setContent(toBlobLiteByMethod(data, str.getContent));
}

// Imitate Data::set(const DataLite& dataLite).
static void
setData(PyObject* data, const DataLite& dataLite)
{
  // TODO: Handle types other than Sha256WithRsaSignature.
  PyObject* signatureName = str.Sha256WithRsaSignature;
  PyObjectRef pyndnModule(PyImport_ImportModule("pyndn"));
  PyObjectRef signatureClass(PyObject_GetAttr(pyndnModule, signatureName));
  PyObjectRef tempSignature(PyObject_CallObject(signatureClass, NULL));
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs
    (data, str.setSignature, tempSignature.obj, NULL));

  // Now use the signature object that was copied into data.
  PyObjectRef signature(PyObject_CallMethodObjArgs(data, str.getSignature, NULL));
  setSha256WithRsaSignature(signature, dataLite.getSignature());

  PyObjectRef name(PyObject_CallMethodObjArgs(data, str.getName, NULL));
  setName(name, dataLite.getName());

  PyObjectRef metaInfo(PyObject_CallMethodObjArgs(data, str.getMetaInfo, NULL));
  setMetaInfo(metaInfo, dataLite.getMetaInfo());

  PyObjectRef blob(makeBlob(dataLite.getContent()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (data, str.setContent, blob.obj, NULL));
}

static PyObject *
_pyndn_Tlv0_1_1WireFormat_encodeData(PyObject *self, PyObject *args)
{
  PyObject* data;
  if (!PyArg_ParseTuple(args, "O", &data))
    return NULL;

  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent keyNameComponents[100];
  DataLite dataLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  toDataLite(data, dataLite);

  // TODO: Make this a dynamic buffer.
  uint8_t debugEncoding[2000];
  DynamicUInt8ArrayLite output(debugEncoding, sizeof(debugEncoding), 0);
  size_t signedPortionBeginOffset, signedPortionEndOffset, encodingLength;

  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::encodeData
       (dataLite, &signedPortionBeginOffset, &signedPortionEndOffset,
        output, &encodingLength))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  PyObjectRef encoding(PyByteArray_FromStringAndSize
    ((const char*)debugEncoding, encodingLength));
  return Py_BuildValue
    ("(O,i,i)", encoding.obj, (int)signedPortionBeginOffset,
     (int)signedPortionEndOffset);
}

static PyObject *
_pyndn_Tlv0_1_1WireFormat_decodeData(PyObject *self, PyObject *args)
{
  PyObject* data;
  PyObject* input;
  if (!PyArg_ParseTuple(args, "OO", &data, &input))
    return NULL;

  BlobLite inputLite = toBlobLiteFromArray(input);

  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent keyNameComponents[100];
  DataLite dataLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  size_t signedPortionBeginOffset, signedPortionEndOffset;
  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::decodeData
       (dataLite, inputLite.buf(), inputLite.size(), &signedPortionBeginOffset,
        &signedPortionEndOffset))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  setData(data, dataLite);

  return Py_BuildValue
    ("(i,i)", (int)signedPortionBeginOffset, (int)signedPortionEndOffset);
}

extern "C" {
  static PyMethodDef PyndnMethods[] = {
    {"Tlv0_1_1WireFormat_encodeData",  _pyndn_Tlv0_1_1WireFormat_encodeData, METH_VARARGS,
"Encode data in NDN-TLV and return the encoding and signed offsets.\n\
\n\
:param Data data: The Data object to encode.\n\
:return: A Tuple of (encoding, signedPortionBeginOffset,\n\
  signedPortionEndOffset) where encoding is a bytearray (not Blob) containing the\n\
  encoding, signedPortionBeginOffset is the offset in the encoding of\n\
  the beginning of the signed portion, and signedPortionEndOffset is\n\
  the offset in the encoding of the end of the signed portion. If r is the\n\
  result Tuple, the encoding Blob is Blob(r[0], False).\n\
:rtype: (str, int, int)"},
    {"Tlv0_1_1WireFormat_decodeData",  _pyndn_Tlv0_1_1WireFormat_decodeData, METH_VARARGS,
"Decode input as an NDN-TLV data packet, set the fields in the data\n\
object, and return the signed offsets.\n\
\n\
:param Data data:  The Data object whose fields are updated.\n\
:param input: The array with the bytes to decode.\n\
:type input: An array type with int elements\n\
:return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset)\n\
  where signedPortionBeginOffset is the offset in the encoding of\n\
  the beginning of the signed portion, and signedPortionEndOffset is\n\
  the offset in the encoding of the end of the signed portion.\n\
:rtype: (int, int)"},
    {NULL, NULL, 0, NULL} // sentinel
  };

  PyMODINIT_FUNC
  init_pyndn(void)
  {
    (void)Py_InitModule("_pyndn", PyndnMethods);
  }
}
