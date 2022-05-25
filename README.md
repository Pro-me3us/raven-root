# Raven unlock: Temporary unlock the FireTV 2nd gen Cube
Non-persistently enable access to all the system features on the Fire TV 2nd gen Cube.  This includes all u-boot & fastboot commands, Amlogic burn mode, TWRP, FireOS with ADB root and selinux permissive, Magisk support, and booting alternative OS's from USB.  As this tool is non-persistent, it will need to be reloaded from a connected computer after any reboot.

# About the exploit
This expoit is based on a <a href="https://fredericb.info/2021/02/amlogic-usbdl-unsigned-code-loader-for-amlogic-bootrom.html"> vulnerability</a>  in the Amlogic bootrom that allows for us to run unverified code in the following boot stage (Bl2).  To pause the automatic boot up process, before the Cube's saved Bl2 is loaded, we rely on Amlogic's device firmware upgrade mode (DFU).  In DFU, only the boot code from the s922x SOC (Bl1) has been loaded into memory.  We now use the vulnerability to load our modified Bl2, breaking the 'chain of trust', and disabling secure boot so that we can make modifications to the bootloader downstream.  The last stage of the bootloader is U-boot  (Bl33) which hands off the startup process to the boot.img.  U-boot is modified to unlock any restrictions on u-boot and fastboot commands, giving us full access to system features. We can then use fastboot boot to load our modified boot images (TWRP, magisk-patched boot.img), into memory without modifying the Cube.

# Standard Disclaimer
You are solely responsible for any potential damage(s) caused to your device by this exploit.

# Requirements
<li>FireTV 2nd gen Cube with FireOS version earlier than 7.2.7.3<sup>1</sup></li>
<li>Micro-USB cable</li>
<li>Device to put Cube into device firmware upgrade (DFU) mode<sup>2</sup></li>
<li>Linux installation or live-system (Ubuntu 20+ recommended)</li>
<li><code>libusb-dev</code> installed</li>

<br>  
<sup>1</sup>In February to March 2022, Amazon began rolling out firmware version 7.2.7.3/2625 which burned efuses to disable USB boot, and bar DFU entry needed by this exploit.  As of May 2022, new 2nd gen Cubes are still shipped with fireware version 7.2.2.9/1856 and can be prevented from updating to the newest firmware during the registration process by following this <a href="https://www.aftvnews.com/how-to-skip-software-updates-during-initial-setup-or-factory-reset-on-a-fire-tv-firestick-or-fire-tv-cube/">guide</a>.<br><br>
<sup>2</sup>To put the 2nd gen Cube into device firmware upgrade (DFU) mode we need to pass a 'boot@usb' command, to the Cube's Amlogic s922x SOC, through its I2C bus via the HDMI port.  This was first described in the <a href="https://blog.exploitee.rs/2018/rooting-the-firetv-cube-and-pendant-with-firefu">FireFU</a> exploit for the 1st gen Cube & Pendant.  Since then there are a few more options for devices to accmplish this: 

1) Arduino sketch to boot into DFU, compatible with ARM-based Arduino boards (Due, Teensy, Genuino)<br>
https://www.exploitee.rs/index.php/FireFU_Exploit#Preparing_HDMI_dongle

2) I2C emulator for Mega boards (Arduino Duemilanove, ATmega48/88/168/328)<br>
https://github.com/tchebb/amlogic-hdmiboot-avr

3) DIY modified dummy HDMI dongle. Fully self-contained, and powered by the HDMI port.<br>
https://github.com/superna9999/linux/wiki/Amlogic-HDMI-Boot-Dongle<br>

# Explanation
In late 2020 security researcher Frederic Basse discovered a <a href="https://fredericb.info/2021/02/amlogic-usbdl-unsigned-code-loader-for-amlogic-bootrom.html">critical bug</a> in the USB stack of the Amlogic S905D3 & S905D3G SOCs that allows for the execution of unsigned code by the bootrom.  As proof of concept he demonstrated that secure boot could be bypassed on the Google Chromecast to <a href="https://fredericb.info/2021/11/booting-ubuntu-on-google-chromecast-with-google-tv.html">boot a custom OS</a> like Ubuntu through the USB interface.  Security researchers Jan Altensen (Stricted) and Nolen Johnson (npjohnson) extended on this work, disabling secure boot & anti-rollback checks in the bootloader and release a persistent <a href="https://github.com/npjohnson/sabrina-unlock">bootloader unlock</a> method for the Google Chromecast.<br>

In spring 2022 I came across this work while researching potential vulnerabilities in the 2nd gen Cube.  The Cube uses an S922X SOC which is part of the G12B Amlogic SOC family, and closely related to both the G12A and SM1 (S905D3) families.  Considering their similar architerture, I surmised there was a good chance the same S905D3 vulnerability would be present in the S922X.  I got in contact with Nolen & Frederic which led me down the path of replicating and adapting Frederic's previous S905D3 methods and tools to the S922X.  To use the amlogic-usbdl exploit tool and payloads written for the S905D3, we would need to obtain the S922X bootrom to update a few of the hardware addresses for the S922X.

### Dumping S922X bootrom
We take advantage of Frederic's previous article on <a href="https://fredericb.info/2021/02/dump-amlogic-s905d3-bootrom-from-khadas-vim3l-board.html">how to dump the S905D3 bootrom</a>.  The guide utilizes a small Bl2 bootloader script that can be loaded with Amlogic's update tool to dump the bootrom code over UART.  However, running the script requires executing code in secure world, which is not possible with secure boot enabled on the Cube. Instead we need a device like Khadas' VIM3L that has secure boot disabled, but with an S922X SOC like Hardkernel's Odroid N2+. With the Odroid N2+, we follow the S905D3 guide to a tee, only using the <code>aml_encrypt_g12b tool</code>, rather than the <code>aml_encrypt_g12b</code> during the build process.  

##### Build
The code is built using GNU C cross-compiler for the arm64 architecture (packages gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu on Debian) :

<code>sudo aarch64-linux-gnu-gcc -O3 -nostdlib -Wl,--build-id=none -o S922X_dump_bootrom.elf S922X_dump_bootrom.c</code><br>
<code>sudo aarch64-linux-gnu-objcopy -O binary -j .text S922X_dump_bootrom.elf S922X_dump_bootrom.bin</code>

Then, the binary is packaged as regular BL2 image for this target using the aml_encrypt_g12a tool from khadas-uboot repository:

<code>sudo ./khadas-uboot/fip/g12b/aml_encrypt_g12b --bl2sig --input ./S922X_dump_bootrom.bin --</code>

### Updating amlogic-usbdl & payloads
To determine whether the S922X was vulnerable we would next attempt to re-exact the bootrom, only this time using the <code>amlogic-usbdl</code> exploit tool to extract the bootrom.  The unverified code with instructions to dump the bootrom code to UART was in the <code>amlogic-usbdl</code> payload <code>dump_bootrom_uart_s922x.S</code>. First we would need to update the payload written for the S905D3 with the <a href="https://github.com/Pro-me3us/amlogic-usbdl_S922X/commit/49b360360888de96e81e1dfe206e0864e91d4000">UART hardware address</a> for the S922X:

<code>
_uart_putc: .dword 0xffff25f4
</code>
<br><br>
Next, we had to find an address for the download buffer pointer (<code>TARGET_RA_PTR</code>) within the <code>0xFFFE3600-0xFFFE3800</code> stack buffer range that would work with the S922X.  After trying a long list of addresses within the stack buffer without success, we discovered that by modifying the <code>bulk_transfer_size</code> in addition to <code>TARGET_RA_PTR</code> we were finally able to get some UART output.  Analysis of the UART output confirmed it was the bootrom code, confirming that the same USB stack buffer bug was present in the S922X.  The <code>bulk_transfer_size</code> could be decreased to as little as <code>0x6</code>, increasing the maximum payload size to 65530 bytes. We settled on <code>0xFE</code> for the <code>bulk_transfer_size</code> to keep things similar to the S905D3 exploit, and <code>0xFFFE3678</code> for the <a href="https://github.com/Pro-me3us/amlogic-usbdl_S922X/commit/20d7b89d16360266f7cb182eac709ddd0724dd8f">buffer pointer address</a>.

  












