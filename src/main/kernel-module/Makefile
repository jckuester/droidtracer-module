PWD := $(shell pwd)

# CHANGE PATH TO YOUR NDK
ANDROID_NDK := ~/opt/android-ndk
# CHANGE PATH TO KERNEL SOURCES (default: nexus 7)
KDIR := ~/git/tegra
# CHANGE PATH TO KERNEL SOURCES FOR EMULATOR (goldfish)
KDIR_GOLDFISH := ~/git/goldfish-2.6.29

# kernel sources for nexus 4, 5
KDIR_MSM := ~/git/msm
# kernel sources for nexus 7
KDIR_TEGRA := ~/git/tegra
# kernel source for nexus S
KDIR_SAMSUNG := ~/git/samsung

# Android NDK compiler
ANDROID_EABI := $(ANDROID_NDK)/toolchains/arm-linux-androideabi-4.7/prebuilt/linux-x86_64/bin
ANDROID_EABI_OLD := $(ANDROID_NDK)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin
#EABI := ~/git/aosp/prebuilts/gcc/linux-x86/arm/arm-eabi-4.7/bin
EABI := ~/git/arm-eabi-4.7/bin

obj-m += droidtracer.o
droidtracer-objs := helper.o genl-endpoint.o trace-syscalls.o

default:
	$(MAKE) ARCH=arm CFLAGS_MODULE=-fno-pic CFLAGS=-Dname=ARM CROSS_COMPILE=$(ANDROID_EABI)/arm-linux-androideabi- -C $(KDIR) M=$(PWD)  modules

nexus4:
	$(MAKE) ARCH=arm CFLAGS_MODULE=-fno-pic CFLAGS=-Dname=ARM CROSS_COMPILE=$(ANDROID_EABI)/arm-linux-androideabi- -C $(KDIR_MSM) M=$(PWD) modules
	adb push droidtracer.ko /storage/sdcard0/droidtracer.ko
	adb shell su -c "rmmod /storage/sdcard0/droidtracer.ko"
	adb shell su -c "insmod /storage/sdcard0/droidtracer.ko"

nexus5:
	$(MAKE) ARCH=arm CFLAGS_MODULE=-fno-pic CFLAGS=-Dname=ARM CROSS_COMPILE=$(EABI)/arm-eabi- -C $(KDIR_MSM) M=$(PWD) modules
	adb shell su -c "rmmod /storage/sdcard0/droidtracer.ko"
	adb push droidtracer.ko /storage/sdcard0/droidtracer.ko	
	adb shell su -c "insmod /storage/sdcard0/droidtracer.ko"

nexus7:
	$(MAKE) ARCH=arm CFLAGS_MODULE=-fno-pic CFLAGS=-Dname=ARM CROSS_COMPILE=$(ANDROID_EABI)/arm-linux-androideabi- -C $(KDIR_TEGRA) M=$(PWD) modules
	adb push droidtracer.ko /storage/sdcard0/droidtracer.ko
	adb shell su -c "rmmod /storage/sdcard0/droidtracer.ko"
	adb shell su -c "insmod /storage/sdcard0/droidtracer.ko"

nexusS:
	$(MAKE) ARCH=arm EXTRA_CFLAGS=-fno-pic CFLAGS=-Dname=ARM CROSS_COMPILE=$(ANDROID_EABI_OLD)/arm-linux-androideabi- -C $(KDIR_SAMSUNG) M=$(PWD) modules
	adb push droidtracer.ko /sdcard/droidtracer.ko
	adb shell su -c "rmmod droidtracer"
	adb shell su -c "insmod /sdcard/droidtracer.ko"

goldfish: 
	$(MAKE) ARCH=arm CFLAGS=-Dname=GOLDFISH CROSS_COMPILE=$(ANDROID_EABI)/arm-linux-androideabi- -C $(KDIR_GOLDFISH) M=$(PWD) modules
	adb push droidtracer.ko /data
	adb shell rmmod /data/droidtracer.ko
	adb shell insmod /data/droidtracer.ko

test:
	#$(MAKE) ARCH=arm CFLAGS_MODULE=-fno-pic CROSS_COMPILE=$(ANDROID_EABI)/arm-linux-androideabi- -C $(KDIR_TEGRA) M=$(PWD) modules
	$(MAKE) ARCH=arm CROSS_COMPILE=$(ANDROID_EABI)/arm-linux-androideabi- -C $(KDIR_GOLDFISH) M=$(PWD) modules	
	adb push test.ko /data
	adb shell rmmod /data/test.ko
	adb shell insmod /data/test.ko

clean-nexus5:
	$(MAKE) ARCH=arm CROSS_COMPILE=$(ANDROID_EABI)/arm-linux-androideabi- -C $(KDIR_MSM) M=$(PWD) clean

