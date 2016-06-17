#include <Python.h>
#include <ndn-cpp/lite/encoding/tlv-0_1_1-wire-format-lite.hpp>
#include <ndn-cpp/lite/interest-lite.hpp>
#include "py-object-ref.hpp"
#include "dynamic-bytearray.hpp"

using namespace ndn;

// Static Python string objects.
class strClass {
public:
  strClass() {
    _array = Py_BuildValue("s", "_array");
    _components = Py_BuildValue("s", "_components");
    _entries = Py_BuildValue("s", "_entries");
    _view = Py_BuildValue("s", "_view");
    Blob = Py_BuildValue("s", "Blob");
    DigestSha256Signature = Py_BuildValue("s", "DigestSha256Signature");
    GenericSignature = Py_BuildValue("s", "GenericSignature");
    HmacWithSha256Signature = Py_BuildValue("s", "HmacWithSha256Signature");
    Sha256WithRsaSignature = Py_BuildValue("s", "Sha256WithRsaSignature");
    Sha256WithEcdsaSignature = Py_BuildValue("s", "Sha256WithEcdsaSignature");
    append = Py_BuildValue("s", "append");
    appendAny = Py_BuildValue("s", "appendAny");
    appendComponent = Py_BuildValue("s", "appendComponent");
    clear = Py_BuildValue("s", "clear");
    getChildSelector = Py_BuildValue("s", "getChildSelector");
    getContent = Py_BuildValue("s", "getContent");
    getComponent = Py_BuildValue("s", "getComponent");
    getExclude = Py_BuildValue("s", "getExclude");
    getFinalBlockId = Py_BuildValue("s", "getFinalBlockId");
    getFreshnessPeriod = Py_BuildValue("s", "getFreshnessPeriod");
    getInterestLifetimeMilliseconds = Py_BuildValue("s", "getInterestLifetimeMilliseconds");
    getKeyData = Py_BuildValue("s", "getKeyData");
    getKeyLocator = Py_BuildValue("s", "getKeyLocator");
    getKeyName = Py_BuildValue("s", "getKeyName");
    getMaxSuffixComponents = Py_BuildValue("s", "getMaxSuffixComponents");
    getMetaInfo = Py_BuildValue("s", "getMetaInfo");
    getMinSuffixComponents = Py_BuildValue("s", "getMinSuffixComponents");
    getMustBeFresh = Py_BuildValue("s", "getMustBeFresh");
    getName = Py_BuildValue("s", "getName");
    getNonce = Py_BuildValue("s", "getNonce");
    getOtherTypeCode = Py_BuildValue("s", "getOtherTypeCode");
    getSelectedDelegationIndex = Py_BuildValue("s", "getSelectedDelegationIndex");
    getSignature = Py_BuildValue("s", "getSignature");
    getSignatureInfoEncoding = Py_BuildValue("s", "getSignatureInfoEncoding");
    getType = Py_BuildValue("s", "getType");
    getTypeCode = Py_BuildValue("s", "getTypeCode");
    getValue = Py_BuildValue("s", "getValue");
    setContent = Py_BuildValue("s", "setContent");
    setFinalBlockId = Py_BuildValue("s", "setFinalBlockId");
    setFreshnessPeriod = Py_BuildValue("s", "setFreshnessPeriod");
    setKeyData = Py_BuildValue("s", "setKeyData");
    setOtherTypeCode = Py_BuildValue("s", "setOtherTypeCode");
    setSignature = Py_BuildValue("s", "setSignature");
    setSignatureInfoEncoding = Py_BuildValue("s", "setSignatureInfoEncoding");
    setType = Py_BuildValue("s", "setType");
  }
  PyObject* _array;
  PyObject* _components;
  PyObject* _entries;
  PyObject* _view;
  PyObject* Blob;
  PyObject* DigestSha256Signature;
  PyObject* GenericSignature;
  PyObject* HmacWithSha256Signature;
  PyObject* Sha256WithRsaSignature;
  PyObject* Sha256WithEcdsaSignature;
  PyObject* append;
  PyObject* appendAny;
  PyObject* appendComponent;
  PyObject* getChildSelector;
  PyObject* clear;
  PyObject* getComponent;
  PyObject* getExclude;
  PyObject* getContent;
  PyObject* getFinalBlockId;
  PyObject* getFreshnessPeriod;
  PyObject* getInterestLifetimeMilliseconds;
  PyObject* getKeyData;
  PyObject* getKeyLocator;
  PyObject* getKeyName;
  PyObject* getMaxSuffixComponents;
  PyObject* getMetaInfo;
  PyObject* getMinSuffixComponents;
  PyObject* getMustBeFresh;
  PyObject* getName;
  PyObject* getNonce;
  PyObject* getOtherTypeCode;
  PyObject* getSelectedDelegationIndex;
  PyObject* getSignature;
  PyObject* getSignatureInfoEncoding;
  PyObject* getType;
  PyObject* getTypeCode;
  PyObject* getValue;
  PyObject* setContent;
  PyObject* setFinalBlockId;
  PyObject* setFreshnessPeriod;
  PyObject* setKeyData;
  PyObject* setOtherTypeCode;
  PyObject* setSignature;
  PyObject* setSignatureInfoEncoding;
  PyObject* setType;
};

static strClass str;
static PyObjectRef PYNDN_MODULE(PyImport_ImportModule("pyndn"));
static PyObjectRef PYNDN_UTIL_MODULE(PyImport_ImportModule("pyndn.util"));
static const long Exclude_COMPONENT = 1;

/**
 * Get a long value by calling obj.methodName() and using PyInt_AsLong.
 * @param obj The object with the method to call.
 * @param methodName A Python string object of the method name to call.
 * @return The long value, or -1 if the value returned by the method call is not
 * a Python float (such as None).
 */
static long
toLongByMethod(PyObject* obj, PyObject* methodName)
{
  PyObjectRef val(PyObject_CallMethodObjArgs(obj, methodName, NULL));
  return PyInt_AsLong(val);
}

/**
 * Get a double value by calling obj.methodName() and using PyFloat_AsDouble.
 * @param obj The object with the method to call.
 * @param methodName A Python string object of the method name to call.
 * @return The double value, or -1.0 if the value returned by the method call is
 * not a Python float (such as None).
 */
static double
toDoubleByMethod(PyObject* obj, PyObject* methodName)
{
  PyObjectRef val(PyObject_CallMethodObjArgs(obj, methodName, NULL));
  return PyFloat_AsDouble(val);
}

/**
 * Calling obj.methodName() and check if it is Py_True.
 * @param obj The object with the method to call.
 * @param methodName A Python string object of the method name to call.
 * @return True if the object is Py_True, otherwise false.
 */
static long
toBoolByMethod(PyObject* obj, PyObject* methodName)
{
  PyObjectRef val(PyObject_CallMethodObjArgs(obj, methodName, NULL));
  return val.obj == Py_True;
}

/**
 * Call PyObject_CallMethodObjArgs(obj, methodName, valueObj, NULL) where
 * valueObj is the PyLong for the long value. Ignore the result from
 * CallMethodObjArgs.
 * @param obj The object with the method to call.
 * @param methodName A Python string object of the method name to call.
 * @param value The long value for the method call.
 */
void
callMethodFromLong(PyObject* obj, PyObject* methodName, long value)
{
  PyObjectRef valueObj(PyLong_FromLong(value));
  PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
    (obj, methodName, valueObj.obj, NULL));
}

/**
 * Call PyObject_CallMethodObjArgs(obj, methodName, valueObj, NULL) where
 * valueObj is the PyFloat for the double value. Ignore the result from
 * CallMethodObjArgs.
 * @param obj The object with the method to call.
 * @param methodName A Python string object of the method name to call.
 * @param value The double value for the method call.
 */
void
callMethodFromDouble(PyObject* obj, PyObject* methodName, double value)
{
  PyObjectRef valueObj(PyFloat_FromDouble(value));
  PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
    (obj, methodName, valueObj.obj, NULL));
}

/**
 * Imitate Python isinstance(obj, module.class) by loading a Python class from
 * an imported module.
 * @param obj The Python object to check.
 * @param moduleName The module name to import.
 * @param className A Python string object of the class name.
 * @return True if obj is an instance of the class.
 */
static bool
isInstance(PyObject* obj, const char* moduleName, PyObject* className)
{
  // TODO: Cache the loaded module?
  PyObjectRef module(PyImport_ImportModule(moduleName));
  PyObjectRef pyClass(PyObject_GetAttr(module, className));
  return PyObject_IsInstance(obj, pyClass) != 0;
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
  PyObjectRef Blob(PyObject_GetAttr(PYNDN_UTIL_MODULE, str.Blob));
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

// Imitate Exclude::get(ExcludeLite& excludeLite).
static void
toExcludeLite(PyObject* exclude, ExcludeLite& excludeLite)
{
  excludeLite.clear();
  PyObjectRef entries(PyObject_GetAttr(exclude, str._entries));
  for (size_t i = 0; i < PyList_GET_SIZE(entries.obj); ++i) {
    PyObject* entry = PyList_GET_ITEM(entries.obj, i);
    ndn_Error error;
    if (toLongByMethod(entry, str.getType) == Exclude_COMPONENT) {
      PyObjectRef component(PyObject_CallMethodObjArgs
        (entry, str.getComponent, NULL));
      if ((error = excludeLite.appendComponent
           (toBlobLiteByMethod(component, str.getValue))))
        // TODO: Handle the error!
        return;
    }
    else {
      if ((error = excludeLite.appendAny()))
        // TODO: Handle the error!
        return;
    }
  }
}

// Imitate Exclude::set(const ExcludeLite& excludeLite).
static void
setExclude(PyObject* exclude, const ExcludeLite& excludeLite)
{
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs(exclude, str.clear, NULL));

  for (size_t i = 0; i < excludeLite.size(); ++i) {
    const ExcludeLite::Entry& entry = excludeLite.get(i);

    if (entry.getType() == ndn_Exclude_COMPONENT) {
      PyObjectRef blob(makeBlob(entry.getComponent().getValue()));
      PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
        (exclude, str.appendComponent, blob.obj, NULL));
    }
    else if (entry.getType() == ndn_Exclude_ANY)
      PyObjectRef ignoreResult3(PyObject_CallMethodObjArgs
        (exclude, str.appendAny, NULL));
    else
      // unrecognized ndn_ExcludeType"
      // TODO: Handle the error!
      return;
  }
}

// Imitate KeyLocator::get(KeyLocatorLite& keyLocatorLite).
static void
toKeyLocatorLite(PyObject* keyLocator, KeyLocatorLite& keyLocatorLite)
{
  // If the value is None, PyInt_AsLong returns -1 as desired.
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
  // If type is -1, KeyLocator.setType will set to None as desired.
  callMethodFromLong(keyLocator, str.setType, keyLocatorLite.getType());

  PyObjectRef keyData(makeBlob(keyLocatorLite.getKeyData()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (keyLocator, str.setKeyData, keyData.obj, NULL));

  PyObjectRef keyName(PyObject_CallMethodObjArgs(keyLocator, str.getKeyName, NULL));
  if (keyLocatorLite.getType() == ndn_KeyLocatorType_KEYNAME)
    setName(keyName, keyLocatorLite.getKeyName());
  else
    PyObjectRef ignoreResult3(PyObject_CallMethodObjArgs(keyName, str.clear, NULL));
}

// Imitate Interest::get(InterestLite& interestLite).
static void
toInterestLite(PyObject* interest, InterestLite& interestLite)
{
  PyObjectRef name(PyObject_CallMethodObjArgs(interest, str.getName, NULL));
  toNameLite(name, interestLite.getName());

  // If the value is None, PyInt_AsLong returns -1 as desired.
  interestLite.setMinSuffixComponents
    ((int)toLongByMethod(interest, str.getMinSuffixComponents));
  interestLite.setMaxSuffixComponents
    ((int)toLongByMethod(interest, str.getMaxSuffixComponents));

  PyObjectRef keyLocator(PyObject_CallMethodObjArgs(interest, str.getKeyLocator, NULL));
  toKeyLocatorLite(keyLocator, interestLite.getKeyLocator());

  PyObjectRef exclude(PyObject_CallMethodObjArgs(interest, str.getExclude, NULL));
  toExcludeLite(exclude, interestLite.getExclude());

  interestLite.setChildSelector
    ((int)toLongByMethod(interest, str.getChildSelector));
  interestLite.setMustBeFresh(toBoolByMethod(interest, str.getMustBeFresh));
  interestLite.setInterestLifetimeMilliseconds
    ((int)toDoubleByMethod(interest, str.getInterestLifetimeMilliseconds));

  // TODO: setLinkWireEncoding
  interestLite.setSelectedDelegationIndex
    ((int)toLongByMethod(interest, str.getSelectedDelegationIndex));
}

// Imitate Sha256WithRsaSignature::get(SignatureLite& signatureLite),
//         Sha256WithEcdsaSignature::get(SignatureLite& signatureLite),
//         HmacWithSha256Signature::get(SignatureLite& signatureLite).
static void
toSignatureLiteWithKeyLocator
  (PyObject* signature, ndn_SignatureType type, SignatureLite& signatureLite)
{
  signatureLite.clear();

  signatureLite.setType(type);
  signatureLite.setSignature(toBlobLiteByMethod(signature, str.getSignature));

  PyObjectRef keyLocator
    (PyObject_CallMethodObjArgs(signature, str.getKeyLocator, NULL));
  toKeyLocatorLite(keyLocator, signatureLite.getKeyLocator());
}

// Imitate Sha256WithRsaSignature::set(const SignatureLite& signatureLite),
//         Sha256WithEcdsaSignature::set(const SignatureLite& signatureLite),
//         HmacWithSha256Signature::set(const SignatureLite& signatureLite).
static void
setSignatureWithKeyLocator(PyObject* signature, const SignatureLite& signatureLite)
{
  PyObjectRef signatureBlob(makeBlob(signatureLite.getSignature()));
  PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
    (signature, str.setSignature, signatureBlob.obj, NULL));

  PyObjectRef keyLocator(PyObject_CallMethodObjArgs
    (signature, str.getKeyLocator, NULL));
  setKeyLocator(keyLocator, signatureLite.getKeyLocator());
}

// Imitate DigestSha256Signature::get(SignatureLite& signatureLite).
static void
toSignatureLiteWithSignatureOnly
  (PyObject* signature, ndn_SignatureType type, SignatureLite& signatureLite)
{
  signatureLite.clear();

  signatureLite.setType(type);
  signatureLite.setSignature(toBlobLiteByMethod(signature, str.getSignature));
}

// Imitate DigestSha256Signature::set(const SignatureLite& signatureLite).
static void
setSignatureWithSignatureOnly(PyObject* signature, const SignatureLite& signatureLite)
{
  PyObjectRef signatureBlob(makeBlob(signatureLite.getSignature()));
  PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
    (signature, str.setSignature, signatureBlob.obj, NULL));
}

// Imitate GenericSignature::get(SignatureLite& signatureLite).
static void
toGenericSignatureLite(PyObject* signature, SignatureLite& signatureLite)
{
  signatureLite.clear();

  signatureLite.setType(ndn_SignatureType_Generic);
  signatureLite.setSignature(toBlobLiteByMethod(signature, str.getSignature));
  signatureLite.setSignatureInfoEncoding
    (toBlobLiteByMethod(signature, str.getSignatureInfoEncoding),
     (int)toLongByMethod(signature, str.getTypeCode));
}

// Imitate GenericSignature::set(const SignatureLite& signatureLite).
static void
setGenericSignature(PyObject* signature, const SignatureLite& signatureLite)
{
  PyObjectRef signatureBlob(makeBlob(signatureLite.getSignature()));
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs
    (signature, str.setSignature, signatureBlob.obj, NULL));

  PyObjectRef signatureInfoEncoding
    (makeBlob(signatureLite.getSignatureInfoEncoding()));
  PyObjectRef typeCode(PyLong_FromLong(signatureLite.getGenericTypeCode()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (signature, str.setSignatureInfoEncoding, signatureInfoEncoding.obj,
     typeCode.obj, NULL));
}

// Imitate MetaInfo::get(MetaInfoLite& metaInfoLite).
static void
toMetaInfoLite(PyObject* metaInfo, MetaInfoLite& metaInfoLite)
{
  metaInfoLite.setType((ndn_ContentType)(int)toLongByMethod(metaInfo, str.getType));
  metaInfoLite.setOtherTypeCode((int)toLongByMethod(metaInfo, str.getOtherTypeCode));
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
  callMethodFromLong(metaInfo, str.setType, metaInfoLite.getType());
  callMethodFromLong
    (metaInfo, str.setOtherTypeCode, metaInfoLite.getOtherTypeCode());
  callMethodFromDouble
    (metaInfo, str.setFreshnessPeriod, metaInfoLite.getFreshnessPeriod());

  PyObjectRef finalBlockId(makeBlob(metaInfoLite.getFinalBlockId().getValue()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (metaInfo, str.setFinalBlockId, finalBlockId.obj, NULL));
}

// Imitate Data::get(DataLite& dataLite).
static void
toDataLite(PyObject* data, DataLite& dataLite)
{
  PyObjectRef signature(PyObject_CallMethodObjArgs(data, str.getSignature, NULL));
  if (isInstance(signature, "pyndn", str.Sha256WithRsaSignature))
    toSignatureLiteWithKeyLocator
      (signature, ndn_SignatureType_Sha256WithRsaSignature,
       dataLite.getSignature());
  else if (isInstance(signature, "pyndn", str.Sha256WithEcdsaSignature))
    toSignatureLiteWithKeyLocator
      (signature, ndn_SignatureType_Sha256WithEcdsaSignature,
       dataLite.getSignature());
  else if (isInstance(signature, "pyndn", str.HmacWithSha256Signature))
    toSignatureLiteWithKeyLocator
      (signature, ndn_SignatureType_HmacWithSha256Signature,
       dataLite.getSignature());
  else if (isInstance(signature, "pyndn", str.DigestSha256Signature))
    toSignatureLiteWithSignatureOnly
      (signature, ndn_SignatureType_DigestSha256Signature,
       dataLite.getSignature());
  else if (isInstance(signature, "pyndn", str.GenericSignature))
    toGenericSignatureLite(signature, dataLite.getSignature());
  else
    // TODO: Handle the error "Unrecognized signature type".
    return;

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
  PyObject* signatureName;
  if (dataLite.getSignature().getType() == ndn_SignatureType_Sha256WithRsaSignature)
    signatureName = str.Sha256WithRsaSignature;
  else if (dataLite.getSignature().getType() == ndn_SignatureType_Sha256WithEcdsaSignature)
    signatureName = str.Sha256WithEcdsaSignature;
  else if (dataLite.getSignature().getType() == ndn_SignatureType_HmacWithSha256Signature)
    signatureName = str.HmacWithSha256Signature;
  else if (dataLite.getSignature().getType() == ndn_SignatureType_DigestSha256Signature)
    signatureName = str.DigestSha256Signature;
  else if (dataLite.getSignature().getType() == ndn_SignatureType_Generic)
    signatureName = str.GenericSignature;
  else
    // TODO: Handle the error "Unrecognized signature type".
    return;

  PyObjectRef signatureClass(PyObject_GetAttr(PYNDN_MODULE, signatureName));
  PyObjectRef tempSignature(PyObject_CallObject(signatureClass, NULL));
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs
    (data, str.setSignature, tempSignature.obj, NULL));

  // Now use the signature object that was copied into data.
  PyObjectRef signature(PyObject_CallMethodObjArgs(data, str.getSignature, NULL));
  if (dataLite.getSignature().getType() == ndn_SignatureType_Sha256WithRsaSignature ||
      dataLite.getSignature().getType() == ndn_SignatureType_Sha256WithEcdsaSignature ||
      dataLite.getSignature().getType() == ndn_SignatureType_HmacWithSha256Signature)
    setSignatureWithKeyLocator(signature, dataLite.getSignature());
  else if (dataLite.getSignature().getType() == ndn_SignatureType_DigestSha256Signature)
    setSignatureWithSignatureOnly(signature, dataLite.getSignature());
  else if (dataLite.getSignature().getType() == ndn_SignatureType_Generic)
    setGenericSignature(signature, dataLite.getSignature());
  else
    // We don't expect this to happen since we just checked above.
    return;

  PyObjectRef name(PyObject_CallMethodObjArgs(data, str.getName, NULL));
  setName(name, dataLite.getName());

  PyObjectRef metaInfo(PyObject_CallMethodObjArgs(data, str.getMetaInfo, NULL));
  setMetaInfo(metaInfo, dataLite.getMetaInfo());

  PyObjectRef blob(makeBlob(dataLite.getContent()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (data, str.setContent, blob.obj, NULL));
}

static PyObject *
_pyndn_Tlv0_1_1WireFormat_encodeInterest(PyObject *self, PyObject *args)
{
  PyObject* interest;
  if (!PyArg_ParseTuple(args, "O", &interest))
    return NULL;

  struct ndn_NameComponent nameComponents[100];
  struct ndn_ExcludeEntry excludeEntries[100];
  struct ndn_NameComponent keyNameComponents[100];
  InterestLite interestLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     excludeEntries, sizeof(excludeEntries) / sizeof(excludeEntries[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  toInterestLite(interest, interestLite);

  DynamicBytearray output(256);
  size_t signedPortionBeginOffset, signedPortionEndOffset, encodingLength;

  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::encodeInterest
       (interestLite, &signedPortionBeginOffset, &signedPortionEndOffset,
        output, &encodingLength))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  return Py_BuildValue
    ("(O,i,i)", output.finish(encodingLength), (int)signedPortionBeginOffset,
     (int)signedPortionEndOffset);
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

  DynamicBytearray output(1500);
  size_t signedPortionBeginOffset, signedPortionEndOffset, encodingLength;

  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::encodeData
       (dataLite, &signedPortionBeginOffset, &signedPortionEndOffset,
        output, &encodingLength))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  return Py_BuildValue
    ("(O,i,i)", output.finish(encodingLength), (int)signedPortionBeginOffset,
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
    {"Tlv0_1_1WireFormat_encodeInterest",  
     _pyndn_Tlv0_1_1WireFormat_encodeInterest, METH_VARARGS,
"Encode interest in NDN-TLV and return the encoding and signed offsets.\n\
\n\
:param Interest interest: The Interest object to encode.\n\
:return: A Tuple of (encoding, signedPortionBeginOffset,\n\
  signedPortionEndOffset) where encoding is a bytearray (not Blob) containing the\n\
  encoding, signedPortionBeginOffset is the offset in the encoding of\n\
  the beginning of the signed portion, and signedPortionEndOffset is\n\
  the offset in the encoding of the end of the signed portion. The signed\n\
  portion starts from the first name component and ends just before the final\n\
  name component (which is assumed to be a signature for a signed interest).\n\
  If r is the result Tuple, the encoding Blob is Blob(r[0], False).\n\
:rtype: (str, int, int)"},
    {"Tlv0_1_1WireFormat_encodeData",  _pyndn_Tlv0_1_1WireFormat_encodeData,
     METH_VARARGS,
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
    {"Tlv0_1_1WireFormat_decodeData",  _pyndn_Tlv0_1_1WireFormat_decodeData,
     METH_VARARGS,
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
