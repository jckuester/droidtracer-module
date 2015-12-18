# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnl/include 

LOCAL_MODULE := nl
LOCAL_SRC_FILES := $(wildcard libnl/lib/*.c)
LOCAL_SRC_FILES += $(wildcard libnl/lib/genl/*.c)
LOCAL_SRC_FILES := $(filter-out libnl/lib/addr.c, $(LOCAL_SRC_FILES))

LOCAL_CFLAGS   := -I ~/git/goldfish-2.6.29/include

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
# using c++ stl
APP_STL := stlport_static
LOCAL_C_INCLUDES += $(LOCAL_PATH)/libnl/include $(LOCAL_PATH)/../kernel-module ~/opt/android-ndk/sources/cxx-stl/gnu-libstdc++/4.7/include
LOCAL_MODULE := droidtracer
LOCAL_STATIC_LIBRARIES := nl
#LOCAL_LDLIBS := -llog -lbinder -lutils
LOCAL_LDLIBS := -llog
LOCAL_LDLIBS += -L$(LOCAL_PATH)/lib

LOCAL_SRC_FILES := droidtracer.cpp


include $(BUILD_SHARED_LIBRARY)

