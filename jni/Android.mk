LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

ifeq ($(ARCH_X86_HAVE_AES_NI),true)

LOCAL_SRC_FILES := aesni.c \
		intel_aes.c

LOCAL_STATIC_LIBRARIES := liblog

LOCAL_MODULE    := libaesni_jni
LOCAL_MODULE_TAGS := optional

LOCAL_LDFLAGS := -Wl,--no-warn-shared-textrel

include $(BUILD_SHARED_LIBRARY)

endif
