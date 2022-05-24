# Raven unlock: Temporary unlock the FireTV 2nd gen Cube
Non-persistently enable access to all the system features on the Fire TV 2nd gen Cube.  This includes all u-boot & fastboot commands, Amlogic burn mode, TWRP, FireOS with ADB root and selinux permissive, Magisk support, and booting alternative OS's from USB.  As this tool is non-persistent, it will need to be reloaded from a connected computer after any reboot.

# About the exploit
This expoit is based on a <a href="https://fredericb.info/2021/02/amlogic-usbdl-unsigned-code-loader-for-amlogic-bootrom.html"> vulnerability</a>  in the Amlogic bootrom that allows for us to run unverified code in the following boot stage (Bl2).  To pause the automatic boot up process, before the Cube's saved Bl2 is loaded, we rely on Amlogic's device firmware upgrade mode (DFU).  In DFU, only the boot code from the s922x SOC (Bl1) has been loaded into memory.  We now use the vulnerability to load our modified Bl2, breaking the 'chain of trust', and disabling secure boot so that we can make modifications to the bootloader downstream.  The last stage of the bootloader is U-boot  (Bl33) which hands off the startup process to the boot.img.  U-boot is modified to unlock any restrictions on u-boot and fastboot commands, giving us full access to system features. We can then use fastboot boot to load our modified boot images (TWRP, magisk-patched boot.img), into memory without modifying the Cube.

# Standard Disclaimer
You are solely responsible for any potential damage(s) caused to your device by this exploit.

# Requirements
<li>FireTV 2nd gen Cube with FireOS version earlier than 7.2.7.3[^1]</li>
<li>Micro-USB cable</li>
<li>Device to put Cube into device firmware upgrade (DFU) mode<sup>2</sup></li>
<li>Linux installation or live-system (Ubuntu 20+ recommended)</li>
<li><code>libusb-dev</code> installed</li>

<br>  
[^1]: <sup>1</sup>In February to March 2022, Amazon began rolling out firmware version 7.2.7.3/2625 which burned efuses to disable USB boot, and bar DFU entry needed by this exploit.  As of May 2022, new 2nd gen Cubes are still shipped with fireware version 7.2.2.9/1856 and can be prevented from updating to the newest firmware during the registration process by following this <a href="https://www.aftvnews.com/how-to-skip-software-updates-during-initial-setup-or-factory-reset-on-a-fire-tv-firestick-or-fire-tv-cube/">guide</a>.<br><br>
<sup>2</sup>To put the 2nd gen Cube into device firmware upgrade (DFU) mode we need to pass a 'boot@usb' command, to the Cube's Amlogic s922x SOC, through its I2C bus via the HDMI port.  This was first described in the <a href="https://blog.exploitee.rs/2018/rooting-the-firetv-cube-and-pendant-with-firefu">FireFU</a> exploit for the 1st gen Cube & Pendant.  Since then there are a few more options for devices to accmplish this: 

1) Arduino sketch to boot into DFU, compatible with ARM-based Arduino boards (Due, Teensy, Genuino)<br>
https://www.exploitee.rs/index.php/FireFU_Exploit#Preparing_HDMI_dongle

2) I2C emulator for Mega boards (Arduino Duemilanove, ATmega48/88/168/328)<br>
https://github.com/tchebb/amlogic-hdmiboot-avr

3) DIY modified dummy HDMI dongle. Fully self-contained, and powered by the HDMI port.<br>
https://github.com/superna9999/linux/wiki/Amlogic-HDMI-Boot-Dongle<br>

# Explanation
In late 2020 security researcher Frederic Basse discovered a <a href="https://fredericb.info/2021/02/amlogic-usbdl-unsigned-code-loader-for-amlogic-bootrom.html">critical bug</a> in the USB stack of the Amlogic S905D3 & S905D3G SOCs that allows for the execution of unsigned code by the bootrom.  As proof of concept he demonstrated that secure boot could be bypassed on the Google Chromecast to <a href="https://fredericb.info/2021/11/booting-ubuntu-on-google-chromecast-with-google-tv.html">boot a custom OS</a> like Ubuntu through the USB interface.  Security researchers Jan Altensen (Stricted) and Nolen Johnson (npjohnson) extended on this work, disabling secure boot & anti-rollback checks in the bootloader and release a persistent <a href="https://github.com/npjohnson/sabrina-unlock">bootloader unlock</a> method for the Google Chromecast.<br>

In spring 2022 I came across this work while researching potential vulnerabilities in the 2nd gen Cube  The Cube uses an S922X SOC which is part of the G12B Amlogic SOC family, and closely related to both the G12A and SM1 (S905D3) families.  Considering their similar architerture, I surmised there was a good chance the same S905D3 vulnerability would be present in the S922X.  I got in contact with Nolen & Frederic to which led me down the path of adapting and replicating Frederic's previous S905D3 methods and tools to the S922X.  To use the amlogic-usbdl exploit tool and payloads that Frederic had written for the S905D3, we would need to obtain the S922X bootrom to update a few of the hardware addresses.

### Dumping S922X bootrom
We take advantage of Frederic's previous article on how to dump an Amlogic bootrom.
Frederic wrote a small Bl2 bootloader script that can be loaded with Amlogic's update tool to dump the bootrom code over UART.  However, running the script requires executing code in secure world, which is not possible with secure boot enabled on the Cube. We instead need a device like Khadas' VIM3L that has secure boot disabled, but with an S922X SOC like Hardkernel's Odroid N2+.







