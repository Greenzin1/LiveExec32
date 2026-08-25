ARCHS := arm64
TARGET := iphone:clang:latest:16.0
PACKAGE_FORMAT := ipa

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = LiveExec32

LiveExec32_FILES = \
  LC32Main.m AppDelegate.m LC32ViewController.mm \
  main.cpp arm_dynarmic_cp15.cpp dynarmic.cpp arm_interpreter.cpp filesystem.cpp variables.cpp ap_getparents.c \
  zip_extract.cpp unzip.c ioapi.c \
  bridge.mm bridge.s log.m \
  HostFrameworks/Foundation/Foundation.mm \
  HostFrameworks/CoreGraphics/CoreGraphics.mm \
  HostFrameworks/UIKit/UIKit.mm
LiveExec32_CFLAGS = -Iinclude -I. -Wno-error
LiveExec32_CCFLAGS = -std=c++17
LiveExec32_LDFLAGS =
LiveExec32_CODESIGN_FLAGS = -Sentitlements.plist
LiveExec32_INFOPLIST_FLAGS = -UIFileSharingEnabled YES -ULaunchStoryboardName

include $(THEOS_MAKE_PATH)/application.mk
