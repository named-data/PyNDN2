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
    appendImplicitSha256Digest = Py_BuildValue("s", "appendImplicitSha256Digest");
    clear = Py_BuildValue("s", "clear");
    getChildSelector = Py_BuildValue("s", "getChildSelector");
    getContent = Py_BuildValue("s", "getContent");
    getComponent = Py_BuildValue("s", "getComponent");
    getExclude = Py_BuildValue("s", "getExclude");
    getFinalBlockId = Py_BuildValue("s", "getFinalBlockId");
    getFreshnessPeriod = Py_BuildValue("s", "getFreshnessPeriod");
    getForwardingHint = Py_BuildValue("s", "getForwardingHint");
    getInterestLifetimeMilliseconds = Py_BuildValue("s", "getInterestLifetimeMilliseconds");
    getKeyData = Py_BuildValue("s", "getKeyData");
    getKeyLocator = Py_BuildValue("s", "getKeyLocator");
    getKeyName = Py_BuildValue("s", "getKeyName");
    getLinkWireEncoding = Py_BuildValue("s", "getLinkWireEncoding");
    getMaxSuffixComponents = Py_BuildValue("s", "getMaxSuffixComponents");
    getMetaInfo = Py_BuildValue("s", "getMetaInfo");
    getMinSuffixComponents = Py_BuildValue("s", "getMinSuffixComponents");
    getMustBeFresh = Py_BuildValue("s", "getMustBeFresh");
    getName = Py_BuildValue("s", "getName");
    getNonce = Py_BuildValue("s", "getNonce");
    getNotAfter = Py_BuildValue("s", "getNotAfter");
    getNotBefore = Py_BuildValue("s", "getNotBefore");
    getOtherTypeCode = Py_BuildValue("s", "getOtherTypeCode");
    getSelectedDelegationIndex = Py_BuildValue("s", "getSelectedDelegationIndex");
    getSignature = Py_BuildValue("s", "getSignature");
    getSignatureInfoEncoding = Py_BuildValue("s", "getSignatureInfoEncoding");
    getType = Py_BuildValue("s", "getType");
    getTypeCode = Py_BuildValue("s", "getTypeCode");
    getValidityPeriod = Py_BuildValue("s", "getValidityPeriod");
    getValue = Py_BuildValue("s", "getValue");
    hasPeriod = Py_BuildValue("s", "hasPeriod");
    isImplicitSha256Digest = Py_BuildValue("s", "isImplicitSha256Digest");
    setChildSelector = Py_BuildValue("s", "setChildSelector");
    setContent = Py_BuildValue("s", "setContent");
    setFinalBlockId = Py_BuildValue("s", "setFinalBlockId");
    setFreshnessPeriod = Py_BuildValue("s", "setFreshnessPeriod");
    setInterestLifetimeMilliseconds = Py_BuildValue("s", "setInterestLifetimeMilliseconds");
    setKeyData = Py_BuildValue("s", "setKeyData");
    setLinkWireEncoding = Py_BuildValue("s", "setLinkWireEncoding");
    setMaxSuffixComponents = Py_BuildValue("s", "setMaxSuffixComponents");
    setMinSuffixComponents = Py_BuildValue("s", "setMinSuffixComponents");
    setMustBeFresh = Py_BuildValue("s", "setMustBeFresh");
    setNonce = Py_BuildValue("s", "setNonce");
    setOtherTypeCode = Py_BuildValue("s", "setOtherTypeCode");
    setPeriod = Py_BuildValue("s", "setPeriod");
    setSelectedDelegationIndex = Py_BuildValue("s", "setSelectedDelegationIndex");
    setSignature = Py_BuildValue("s", "setSignature");
    setSignatureInfoEncoding = Py_BuildValue("s", "setSignatureInfoEncoding");
    setType = Py_BuildValue("s", "setType");
    size = Py_BuildValue("s", "size");
    unsetLink = Py_BuildValue("s", "unsetLink");
    wireDecode = Py_BuildValue("s", "wireDecode");
    wireEncode = Py_BuildValue("s", "wireEncode");
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
  PyObject* appendImplicitSha256Digest;
  PyObject* getChildSelector;
  PyObject* clear;
  PyObject* getComponent;
  PyObject* getExclude;
  PyObject* getContent;
  PyObject* getFinalBlockId;
  PyObject* getFreshnessPeriod;
  PyObject* getForwardingHint;
  PyObject* getInterestLifetimeMilliseconds;
  PyObject* getKeyData;
  PyObject* getKeyLocator;
  PyObject* getKeyName;
  PyObject* getLinkWireEncoding;
  PyObject* getMaxSuffixComponents;
  PyObject* getMetaInfo;
  PyObject* getMinSuffixComponents;
  PyObject* getMustBeFresh;
  PyObject* getName;
  PyObject* getNonce;
  PyObject* getNotAfter;
  PyObject* getNotBefore;
  PyObject* getOtherTypeCode;
  PyObject* getSelectedDelegationIndex;
  PyObject* getSignature;
  PyObject* getSignatureInfoEncoding;
  PyObject* getType;
  PyObject* getTypeCode;
  PyObject* getValidityPeriod;
  PyObject* getValue;
  PyObject* hasPeriod;
  PyObject* isImplicitSha256Digest;
  PyObject* setChildSelector;
  PyObject* setContent;
  PyObject* setFinalBlockId;
  PyObject* setFreshnessPeriod;
  PyObject* setInterestLifetimeMilliseconds;
  PyObject* setKeyData;
  PyObject* setLinkWireEncoding;
  PyObject* setMaxSuffixComponents;
  PyObject* setMinSuffixComponents;
  PyObject* setMustBeFresh;
  PyObject* setNonce;
  PyObject* setOtherTypeCode;
  PyObject* setPeriod;
  PyObject* setSelectedDelegationIndex;
  PyObject* setSignature;
  PyObject* setSignatureInfoEncoding;
  PyObject* setType;
  PyObject* size;
  PyObject* unsetLink;
  PyObject* wireDecode;
  PyObject* wireEncode;
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
static bool
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
 * Call PyObject_CallMethodObjArgs(obj, methodName, valueObj1, valueObj2, NULL)
 * where valueObj1 and valueObj2 are the PyFloat for the double value1 and
 * value2. Ignore the result from CallMethodObjArgs.
 * @param obj The object with the method to call.
 * @param methodName A Python string object of the method name to call.
 * @param value1 The double value for arg 1 of the method call.
 * @param value2 The double value for arg 2 of the method call.
 */
void
callMethodFromDouble_Double
  (PyObject* obj, PyObject* methodName, double value1, double value2)
{
  PyObjectRef valueObj1(PyFloat_FromDouble(value1));
  PyObjectRef valueObj2(PyFloat_FromDouble(value2));
  PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
    (obj, methodName, valueObj1.obj, valueObj2.obj, NULL));
}

/**
 * Call PyObject_CallMethodObjArgs(obj, methodName, valueObj, NULL) where
 * valueObj is the Py_True or Py_False depending on Value. Ignore the result
 * from CallMethodObjArgs.
 * @param obj The object with the method to call.
 * @param methodName A Python string object of the method name to call.
 * @param value The bool value for the method call.
 */
void
callMethodFromBool(PyObject* obj, PyObject* methodName, bool value)
{
  PyObjectRef valueObj(PyBool_FromLong(value ? 1 : 0));
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

// Imitate Name::Component::get(NameLite::Component& componentLite).
static void
toNameComponentLite(PyObject* nameComponent, NameLite::Component& componentLite)
{
  if (toBoolByMethod(nameComponent, str.isImplicitSha256Digest))
    componentLite.setImplicitSha256Digest
      (toBlobLiteByMethod(nameComponent, str.getValue));
  else
    componentLite = NameLite::Component
      (toBlobLiteByMethod(nameComponent, str.getValue));
}

// Imitate Name::get(NameLite& nameLite).
static void
toNameLite(PyObject* name, NameLite& nameLite)
{
  nameLite.clear();
  PyObjectRef components(PyObject_GetAttr(name, str._components));
  for (size_t i = 0; i < PyList_GET_SIZE(components.obj); ++i) {
    ndn_Error error;
    NameLite::Component componentLite;
    toNameComponentLite(PyList_GET_ITEM(components.obj, i), componentLite);
    if ((error = nameLite.append(componentLite)))
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
    // Imitate Name::Component::set(const NameLite::Component& componentLite).
    if (nameLite.get(i).isImplicitSha256Digest())
      PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
        (name, str.appendImplicitSha256Digest, blob.obj, NULL));
    else
      PyObjectRef ignoreResult3(PyObject_CallMethodObjArgs
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
      NameLite::Component componentLite;
      toNameComponentLite(component, componentLite);
      if ((error = excludeLite.appendComponent(componentLite)))
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
      // Imitate Name::Component::set(const NameLite::Component& componentLite).
      if (entry.getComponent().isImplicitSha256Digest())
        PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
          (exclude, str.appendImplicitSha256Digest, blob.obj, NULL));
      else
        PyObjectRef ignoreResult3(PyObject_CallMethodObjArgs
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
  callMethodFromLong(keyLocator, str.setType, (int)keyLocatorLite.getType());

  PyObjectRef keyData(makeBlob(keyLocatorLite.getKeyData()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (keyLocator, str.setKeyData, keyData.obj, NULL));

  PyObjectRef keyName(PyObject_CallMethodObjArgs(keyLocator, str.getKeyName, NULL));
  if (keyLocatorLite.getType() == ndn_KeyLocatorType_KEYNAME)
    setName(keyName, keyLocatorLite.getKeyName());
  else
    PyObjectRef ignoreResult3(PyObject_CallMethodObjArgs(keyName, str.clear, NULL));
}

// Imitate ValidityPeriod::get(ValidityPeriodLite& validityPeriodLite).
static void
toValidityPeriodLite
  (PyObject* validityPeriod, ValidityPeriodLite& validityPeriodLite)
{
  if (toBoolByMethod(validityPeriod, str.hasPeriod))
    validityPeriodLite.setPeriod
      (toDoubleByMethod(validityPeriod, str.getNotBefore),
       toDoubleByMethod(validityPeriod, str.getNotAfter));
  else
    validityPeriodLite.clear();
}

// Imitate ValidityPeriod::set(const ValidityPeriodLite& validityPeriodLite).
static void
setValidityPeriod
  (PyObject* validityPeriod, const ValidityPeriodLite& validityPeriodLite)
{
  if (validityPeriodLite.hasPeriod())
    callMethodFromDouble_Double
      (validityPeriod, str.setPeriod, validityPeriodLite.getNotBefore(),
       validityPeriodLite.getNotAfter());
  else
    PyObjectRef ignoreResult
      (PyObject_CallMethodObjArgs(validityPeriod, str.clear, NULL));
}

/**
 * Imitate Interest::get(InterestLite& interestLite).
 * @param interest The Python Interest object to get from.
 * @param interestLite The InterestLite to update.
 * @param pool1 This calls pool1.reset to store a temporary value which must
 * remain valid while interestLite is used.
 * @param pool2 This calls pool2.reset to store a temporary value which must
 * remain valid while interestLite is used.
 */
static void
toInterestLite
  (PyObject* interest, InterestLite& interestLite, PyObjectRef& pool1,
   PyObjectRef& pool2)
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
    (toDoubleByMethod(interest, str.getInterestLifetimeMilliseconds));

  PyObjectRef forwardingHint
    (PyObject_CallMethodObjArgs(interest, str.getForwardingHint, NULL));
  if (toLongByMethod(forwardingHint, str.size) > 0) {
    // InterestLite only stores the encoded delegation set. Cache the wire
    // encoding in pool2 long enough to encode the Interest.
    // TODO: Support the wireFormat param.
    // TODO: Catch exceptions from wireEncode.
    pool2.reset(PyObject_CallMethodObjArgs
      (forwardingHint, str.wireEncode, NULL));
    PyObjectRef forwardingHintWireEncodingArray
      (PyObject_GetAttr(pool2, str._array));
    interestLite.setForwardingHintWireEncoding
      (toBlobLiteFromArray(forwardingHintWireEncodingArray));
  }
  else
    interestLite.setForwardingHintWireEncoding(BlobLite());

  // TODO: Support the wireFormat param.
  // TODO: Catch exceptions from getLinkWireEncoding.
  pool1.reset(PyObject_CallMethodObjArgs(interest, str.getLinkWireEncoding, NULL));
  PyObjectRef linkWireEncodingArray(PyObject_GetAttr(pool1, str._array));
  if (linkWireEncodingArray.obj == Py_None)
    interestLite.setLinkWireEncoding(BlobLite());
  else
    interestLite.setLinkWireEncoding(toBlobLiteFromArray(linkWireEncodingArray));
  interestLite.setSelectedDelegationIndex
    ((int)toLongByMethod(interest, str.getSelectedDelegationIndex));
}

// Imitate Interest::set(const InterestLite& interestLite).
static void
setInterest(PyObject* interest, const InterestLite& interestLite)
{
  PyObjectRef name(PyObject_CallMethodObjArgs(interest, str.getName, NULL));
  setName(name, interestLite.getName());

  // If the value is -1, Interest.setMinSuffixComponents will set to None as desired.
  callMethodFromLong
    (interest, str.setMinSuffixComponents, interestLite.getMinSuffixComponents());
  callMethodFromLong
    (interest, str.setMaxSuffixComponents, interestLite.getMaxSuffixComponents());

  PyObjectRef keyLocator(PyObject_CallMethodObjArgs
    (interest, str.getKeyLocator, NULL));
  setKeyLocator(keyLocator, interestLite.getKeyLocator());

  PyObjectRef exclude(PyObject_CallMethodObjArgs
    (interest, str.getExclude, NULL));
  setExclude(exclude, interestLite.getExclude());

  callMethodFromLong
    (interest, str.setChildSelector, interestLite.getChildSelector());
  callMethodFromBool
    (interest, str.setMustBeFresh, interestLite.getMustBeFresh());
  callMethodFromDouble
    (interest, str.setInterestLifetimeMilliseconds,
     interestLite.getInterestLifetimeMilliseconds());

  if (interestLite.getForwardingHintWireEncoding().buf()) {
    // InterestLite only stores the encoded delegation set.
    PyObjectRef forwardingHintWireEncoding
      (makeBlob(interestLite.getForwardingHintWireEncoding()));
    PyObjectRef forwardingHint
      (PyObject_CallMethodObjArgs(interest, str.getForwardingHint, NULL));
    // TODO: Catch exceptions from wireDecode.
    PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
      (forwardingHint, str.wireDecode, forwardingHintWireEncoding.obj, NULL));
  }

  if (interestLite.getLinkWireEncoding().buf()) {
    PyObjectRef linkWireEncoding(makeBlob(interestLite.getLinkWireEncoding()));
    // TODO: Support the wireFormat param.
    PyObjectRef ignoreResult(PyObject_CallMethodObjArgs
      (interest, str.setLinkWireEncoding, linkWireEncoding.obj, NULL));
  }
  else
    PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs
      (interest, str.unsetLink, NULL));

  callMethodFromLong
    (interest, str.setSelectedDelegationIndex,
     interestLite.getSelectedDelegationIndex());

  // Set the nonce last so that getNonceChangeCount_ is set correctly.
  PyObjectRef nonce(makeBlob(interestLite.getNonce()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (interest, str.setNonce, nonce.obj, NULL));
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

// Check what signature is an instance of and imitate 
//   Sha256WithRsaSignature::set(const SignatureLite& signatureLite), etc.
static void
toSignatureLite(PyObject* signature, SignatureLite& signatureLite)
{
  if (isInstance(signature, "pyndn", str.Sha256WithRsaSignature)) {
    toSignatureLiteWithKeyLocator
      (signature, ndn_SignatureType_Sha256WithRsaSignature, signatureLite);
    PyObjectRef validityPeriod
      (PyObject_CallMethodObjArgs(signature, str.getValidityPeriod, NULL));
    toValidityPeriodLite(validityPeriod, signatureLite.getValidityPeriod());
  }
  else if (isInstance(signature, "pyndn", str.Sha256WithEcdsaSignature)) {
    toSignatureLiteWithKeyLocator
      (signature, ndn_SignatureType_Sha256WithEcdsaSignature, signatureLite);
    PyObjectRef validityPeriod
      (PyObject_CallMethodObjArgs(signature, str.getValidityPeriod, NULL));
    toValidityPeriodLite(validityPeriod, signatureLite.getValidityPeriod());
  }
  else if (isInstance(signature, "pyndn", str.HmacWithSha256Signature))
    toSignatureLiteWithKeyLocator
      (signature, ndn_SignatureType_HmacWithSha256Signature, signatureLite);
  else if (isInstance(signature, "pyndn", str.DigestSha256Signature))
    toSignatureLiteWithSignatureOnly
      (signature, ndn_SignatureType_DigestSha256Signature, signatureLite);
  else if (isInstance(signature, "pyndn", str.GenericSignature))
    toGenericSignatureLite(signature, signatureLite);
  else
    // TODO: Handle the error "Unrecognized signature type".
    return;
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

/**
 * Get the class name for signatureLite.getType().
 * @param signatureLite The SignatureLite to check.
 * @return A PyObject of the string of the class name, or 0 if not recognized.
 */
static PyObject*
getSignatureClassName(const SignatureLite& signatureLite)
{
  if (signatureLite.getType() == ndn_SignatureType_Sha256WithRsaSignature)
    return str.Sha256WithRsaSignature;
  else if (signatureLite.getType() == ndn_SignatureType_Sha256WithEcdsaSignature)
    return str.Sha256WithEcdsaSignature;
  else if (signatureLite.getType() == ndn_SignatureType_HmacWithSha256Signature)
    return str.HmacWithSha256Signature;
  else if (signatureLite.getType() == ndn_SignatureType_DigestSha256Signature)
    return str.DigestSha256Signature;
  else if (signatureLite.getType() == ndn_SignatureType_Generic)
    return str.GenericSignature;
  else
    return 0;
}

// Check signatureLite.getType() and imitate 
//   Sha256WithRsaSignature::set(const SignatureLite& signatureLite), etc.
static void
setSignature(PyObject* signature, const SignatureLite& signatureLite)
{
  if (signatureLite.getType() == ndn_SignatureType_Sha256WithRsaSignature ||
      signatureLite.getType() == ndn_SignatureType_Sha256WithEcdsaSignature) {
    setSignatureWithKeyLocator(signature, signatureLite);
    PyObjectRef validityPeriod(PyObject_CallMethodObjArgs
      (signature, str.getValidityPeriod, NULL));
    setValidityPeriod(validityPeriod, signatureLite.getValidityPeriod());
  }
  else if (signatureLite.getType() == ndn_SignatureType_HmacWithSha256Signature)
    setSignatureWithKeyLocator(signature, signatureLite);
  else if (signatureLite.getType() == ndn_SignatureType_DigestSha256Signature)
    setSignatureWithSignatureOnly(signature, signatureLite);
  else if (signatureLite.getType() == ndn_SignatureType_Generic)
    setGenericSignature(signature, signatureLite);
  else
    // We don't expect this to happen if the caller used getSignatureClassName.
    return;
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
  toSignatureLite(signature, dataLite.getSignature());

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
  PyObject* signatureClassName = getSignatureClassName(dataLite.getSignature());
  if (!signatureClassName)
    // TODO: Handle the error "Unrecognized signature type".
    return;

  PyObjectRef signatureClass(PyObject_GetAttr(PYNDN_MODULE, signatureClassName));
  PyObjectRef tempSignature(PyObject_CallObject(signatureClass, NULL));
  PyObjectRef ignoreResult1(PyObject_CallMethodObjArgs
    (data, str.setSignature, tempSignature.obj, NULL));
  // Now use the signature object that was copied into data.
  PyObjectRef signature(PyObject_CallMethodObjArgs(data, str.getSignature, NULL));
  setSignature(signature, dataLite.getSignature());

  PyObjectRef name(PyObject_CallMethodObjArgs(data, str.getName, NULL));
  setName(name, dataLite.getName());

  PyObjectRef metaInfo(PyObject_CallMethodObjArgs(data, str.getMetaInfo, NULL));
  setMetaInfo(metaInfo, dataLite.getMetaInfo());

  PyObjectRef content(makeBlob(dataLite.getContent()));
  PyObjectRef ignoreResult2(PyObject_CallMethodObjArgs
    (data, str.setContent, content.obj, NULL));
}

static PyObject *
_pyndn_Tlv0_1_1WireFormat_encodeName(PyObject *self, PyObject *args)
{
  PyObject* name;
  if (!PyArg_ParseTuple(args, "O", &name))
    return NULL;

  struct ndn_NameComponent nameComponents[100];
  NameLite nameLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]));

  toNameLite(name, nameLite);

  DynamicBytearray output(256);
  size_t dummyBeginOffset, dummyEndOffset, encodingLength;

  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::encodeName
       (nameLite, &dummyBeginOffset, &dummyEndOffset, output, &encodingLength))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  return Py_BuildValue("O", output.finish(encodingLength));
}

static PyObject *
_pyndn_Tlv0_1_1WireFormat_decodeName(PyObject *self, PyObject *args)
{
  PyObject* name;
  PyObject* input;
  if (!PyArg_ParseTuple(args, "OO", &name, &input))
    return NULL;

  BlobLite inputLite = toBlobLiteFromArray(input);

  struct ndn_NameComponent nameComponents[100];
  NameLite nameLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]));

  ndn_Error error;
  size_t dummyBeginOffset, dummyEndOffset;
  if ((error = Tlv0_1_1WireFormatLite::decodeName
       (nameLite, inputLite.buf(), inputLite.size(), &dummyBeginOffset,
        &dummyEndOffset))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  setName(name, nameLite);

  return Py_BuildValue("");
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

  PyObjectRef pool1, pool2;
  toInterestLite(interest, interestLite, pool1, pool2);

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
_pyndn_Tlv0_1_1WireFormat_decodeInterest(PyObject *self, PyObject *args)
{
  PyObject* interest;
  PyObject* input;
  if (!PyArg_ParseTuple(args, "OO", &interest, &input))
    return NULL;

  BlobLite inputLite = toBlobLiteFromArray(input);

  struct ndn_NameComponent nameComponents[100];
  struct ndn_ExcludeEntry excludeEntries[100];
  struct ndn_NameComponent keyNameComponents[100];
  InterestLite interestLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     excludeEntries, sizeof(excludeEntries) / sizeof(excludeEntries[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  size_t signedPortionBeginOffset, signedPortionEndOffset;
  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::decodeInterest
       (interestLite, inputLite.buf(), inputLite.size(), &signedPortionBeginOffset,
        &signedPortionEndOffset))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  setInterest(interest, interestLite);

  return Py_BuildValue
    ("(i,i)", (int)signedPortionBeginOffset, (int)signedPortionEndOffset);
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

static PyObject *
_pyndn_Tlv0_1_1WireFormat_encodeSignatureInfo(PyObject *self, PyObject *args)
{
  PyObject* signature;
  if (!PyArg_ParseTuple(args, "O", &signature))
    return NULL;

  struct ndn_NameComponent keyNameComponents[100];
  SignatureLite signatureLite
    (keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  toSignatureLite(signature, signatureLite);

  DynamicBytearray output(256);
  size_t encodingLength;

  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::encodeSignatureInfo
       (signatureLite, output, &encodingLength))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  return Py_BuildValue("O", output.finish(encodingLength));
}

static PyObject *
_pyndn_Tlv0_1_1WireFormat_encodeSignatureValue(PyObject *self, PyObject *args)
{
  PyObject* signature;
  if (!PyArg_ParseTuple(args, "O", &signature))
    return NULL;

  struct ndn_NameComponent keyNameComponents[100];
  SignatureLite signatureLite
    (keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  toSignatureLite(signature, signatureLite);

  DynamicBytearray output(300);
  size_t encodingLength;

  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::encodeSignatureValue
       (signatureLite, output, &encodingLength))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  return Py_BuildValue("O", output.finish(encodingLength));
}

static PyObject *
_pyndn_Tlv0_1_1WireFormat_decodeSignatureInfoAndValue(PyObject *self, PyObject *args)
{
  PyObject* signatureInfo;
  PyObject* signatureValue;
  if (!PyArg_ParseTuple(args, "OO", &signatureInfo, &signatureValue))
    return NULL;

  BlobLite signatureInfoLite = toBlobLiteFromArray(signatureInfo);
  BlobLite signatureValueLite = toBlobLiteFromArray(signatureValue);

  struct ndn_NameComponent keyNameComponents[100];
  SignatureLite signatureLite
    (keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  ndn_Error error;
  if ((error = Tlv0_1_1WireFormatLite::decodeSignatureInfoAndValue
       (signatureLite, signatureInfoLite.buf(), signatureInfoLite.size(),
        signatureValueLite.buf(), signatureValueLite.size()))) {
    PyErr_SetString(PyExc_RuntimeError, ndn_getErrorString(error));
    return NULL;
  }

  PyObject* signatureClassName = getSignatureClassName(signatureLite);
  if (!signatureClassName)
    // TODO: Handle the error "Unrecognized signature type".
    return NULL;

  PyObjectRef signatureClass(PyObject_GetAttr(PYNDN_MODULE, signatureClassName));
  // Make a PyObject instead of PyObjectRef since we will give it to Py_BuildValue.
  PyObject* result = PyObject_CallObject(signatureClass, NULL);
  setSignature(result, signatureLite);

  return Py_BuildValue("O", result);
}

extern "C" {
  static PyMethodDef PyndnMethods[] = {
    {"Tlv0_1_1WireFormat_encodeName",
     _pyndn_Tlv0_1_1WireFormat_encodeName, METH_VARARGS,
"Encode name in NDN-TLV and return the encoding.\n\
\n\
:param Name name: The Name object to encode.\n\
:return: A bytearray (not Blob) containing the encoding. If r is the result,\n\
the encoding Blob is Blob(r, False).\n\
:rtype: str"},
    {"Tlv0_1_1WireFormat_decodeName",
     _pyndn_Tlv0_1_1WireFormat_decodeName, METH_VARARGS,
"Decode input as an NDN-TLV name and set the fields of the Name object.\n\
\n\
:param Name name: The Name object whose fields are updated.\n\
:param input: The array with the bytes to decode.\n\
:type input: An array type with int elements"},
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
    {"Tlv0_1_1WireFormat_decodeInterest",
     _pyndn_Tlv0_1_1WireFormat_decodeInterest, METH_VARARGS,
"Decode input as an NDN-TLV interest packet, set the fields in the interest\n\
object, and return the signed offsets.\n\
\n\
:param Interest interest: The Interest object whose fields are updated.\n\
:param input: The array with the bytes to decode.\n\
:type input: An array type with int elements\n\
:return: A Tuple of (signedPortionBeginOffset, signedPortionEndOffset)\n\
  where signedPortionBeginOffset is the offset in the encoding of\n\
  the beginning of the signed portion, and signedPortionEndOffset is\n\
  the offset in the encoding of the end of the signed portion. The signed\n\
  portion starts from the first name component and ends just before the final\n\
  name component (which is assumed to be a signature for a signed interest).\n\
:rtype: (int, int)"},
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
    {"Tlv0_1_1WireFormat_encodeSignatureInfo",
     _pyndn_Tlv0_1_1WireFormat_encodeSignatureInfo, METH_VARARGS,
"Encode signature in NDN-TLV and return the encoding.\n\
\n\
:param signature: An object of a subclass of Signature to encode.\n\
:type signature: An object of a subclass of Signature\n\
:return: A bytearray (not Blob) containing the encoding. If r is the result,\n\
the encoding Blob is Blob(r, False).\n\
:rtype: str"},
    {"Tlv0_1_1WireFormat_encodeSignatureValue",
     _pyndn_Tlv0_1_1WireFormat_encodeSignatureValue, METH_VARARGS,
"Encode the signatureValue in the Signature object as an NDN-TLV\n\
SignatureValue (the signature bits) and return the encoding.\n\
\n\
:param signature: An object of a subclass of Signature with the signature\n\
value to encode.\n\
:type signature: An object of a subclass of Signature\n\
:return: A bytearray (not Blob) containing the encoding. If r is the result,\n\
the encoding Blob is Blob(r, False).\n\
:rtype: str"},
    {"Tlv0_1_1WireFormat_decodeSignatureInfoAndValue",
     _pyndn_Tlv0_1_1WireFormat_decodeSignatureInfoAndValue, METH_VARARGS,
"Decode signatureInfo as a signature info and signatureValue as the related\n\
SignatureValue, and return a new object which is a subclass of Signature.\n\
\n\
:param signatureInfo: The array with the signature info input buffer to decode.\n\
:type signatureInfo: An array type with int elements\n\
:param signatureValue: The array with the signature value input buffer to decode.\n\
:type signatureValue: An array type with int elements\n\
:return: A new object which is a subclass of Signature.\n\
:rtype: a subclass of Signature"},
    {NULL, NULL, 0, NULL} // sentinel
  };

  PyMODINIT_FUNC
  init_pyndn(void)
  {
    (void)Py_InitModule("_pyndn", PyndnMethods);
  }
}
