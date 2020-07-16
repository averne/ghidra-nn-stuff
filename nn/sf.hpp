#pragma once

#include <vapours/vapours.hpp>

namespace nn::sf {

namespace detail {

struct PointerAndSize {
    void *ptr;
    u64 size;
};

} // namespace detail

struct NativeHandle {
  Handle handle;
  bool valid;
};

struct IServiceObject_vtable {
    void *AddReference;
    void *Release;
    void *GetProxyInfo;
    void *GetInterfaceTypeInfo;
};

struct IServiceObject {
    IServiceObject_vtable *vt;
};

namespace cmif {

struct CmifOutHeader;

namespace server {

struct CmifServerMessage_vtable {
    void *PrepareForProcess;
    void *OverwriteClientProcessId;
    void *GetBuffers;
    void *GetInNativeHandles;
    void *GetInObjects;
    void *BeginPreparingForReply;
    void *SetBuffers;
    void *SetOutObjects;
    void *SetOutNativeHandles;
    void *BeginPreparingForErrorReply;
    void *EndPreparingForReply;
};

struct CmifServerMessage {
    CmifServerMessage_vtable *vt;
};

} // namespace server

} // namespace cmif

} // namespace nn::sf
