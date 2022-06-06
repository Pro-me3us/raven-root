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
<sup>1</sup>Amazon began rolling out firmware version 7.2.7.3/2625 in February/March 2022, which burned efuses to disable USB boot, and bar DFU entry needed by this exploit.  As of May 2022, new 2nd gen Cubes are still shipped with firmware version 7.2.2.9/1856 and can be prevented from updating to the newest firmware during the registration process by following this <a href="https://www.aftvnews.com/how-to-skip-software-updates-during-initial-setup-or-factory-reset-on-a-fire-tv-firestick-or-fire-tv-cube/">guide</a>.<br><br>

<sup>2</sup>To put the 2nd gen Cube into device firmware upgrade (DFU) mode we need to pass a 'boot@usb' command, to the Cube's Amlogic s922x SOC, through its I2C bus via the HDMI port.  This was first described in the <a href="https://blog.exploitee.rs/2018/rooting-the-firetv-cube-and-pendant-with-firefu">FireFU</a> exploit for the 1st gen Cube & Pendant.  Since then there are a few more options for devices to accmplish this: 

1) Arduino sketch to boot into DFU, compatible with ARM-based Arduino boards (Due, Teensy, Genuino)<br>
https://www.exploitee.rs/index.php/FireFU_Exploit#Preparing_HDMI_dongle

2) I2C emulator for Mega boards (Arduino Duemilanove, ATmega48/88/168/328)<br>
https://github.com/tchebb/amlogic-hdmiboot-avr

3) DIY modified dummy HDMI dongle. Fully self-contained, and powered by the HDMI port.<br>
https://github.com/superna9999/linux/wiki/Amlogic-HDMI-Boot-Dongle<br>


# Instructions
1) Download and unzip this repository. Unzip the images file into the "raven_boot/images" folder that corresponds to your Cube FireOS version:<br>
    "images_7242-2906.zip" for FireOS 7242/2906+<br>
    "images_7212-1333.zip" for any version earlier than 7242/2906<br>

2) Power off the Cube

3) Connect the HDMI dongle / board (DFU entry device) to the Cube's HDMI port, and computer to the Cube's micro-USB port.

4) Power on the Cube, type 'lsusb' in the terminal. Confirm 'ID 1b8e:c003 Amlogic, Inc.' is listed, indicating the Cube is in DFU mode.

5) Reconnect the Cube and TV with HDMI cable.

6) Type 'bash menu' in the terminal, and choose your boot mode.



To switch boot modes, repeat steps 3-7.

For bash menu option 3) booting with Magisk support, install the Magisk Manager APK (v24.3+ recommended) from within FireOS. https://github.com/topjohnwu/Magisk/releases, ignore the notice about required additional steps.

IMPORTANT: This exploit is non-persistent and will require reconnecting your computer after a reboot. The exploit is run entirely in memory, and will not modify your Cube. DO NOT FLASH ANY MODIFIED IMAGES, OR INSTALL MAGISK through TWRP! This will cause an authentication error / soft brick when rebooting without the exploit present.





# Explanation
In late 2020 security researcher Frederic Basse discovered a <a href="https://fredericb.info/2021/02/amlogic-usbdl-unsigned-code-loader-for-amlogic-bootrom.html">critical bug</a> in the USB stack of the Amlogic S905D3 & S905D3G SOCs that allows for the execution of unsigned code by the bootrom.  As proof of concept he demonstrated that secure boot could be bypassed on the Google Chromecast to <a href="https://fredericb.info/2021/11/booting-ubuntu-on-google-chromecast-with-google-tv.html">boot a custom OS</a> like Ubuntu through the USB interface.  Jan Altensen (Stricted) and Nolen Johnson (npjohnson) later extended on this work, releasing a persistent <a href="https://github.com/npjohnson/sabrina-unlock">bootloader unlock</a> method for the Google Chromecast.<br>

In spring 2022 I came across this work while researching potential vulnerabilities in the 2nd gen Cube.  The Cube uses an S922X SOC which is part of the G12B Amlogic SOC family, and closely related to both the G12A and SM1 (S905D3) families.  Considering their similar architerture, I had a hunch there was a good chance the same S905D3 vulnerability would be present in the S922X.  I got in contact with Nolen & Frederic which led me down the path of replicating and adapting Frederic's previous S905D3 methods and tools to the S922X.  To use the amlogic-usbdl exploit tool and payloads written for the S905D3, we would need to obtain the S922X bootrom to update a few of the hardware addresses that are specific to the S922X SOC.

### Dumping S922X bootrom
We take advantage of Frederic's previous article on <a href="https://fredericb.info/2021/02/dump-amlogic-s905d3-bootrom-from-khadas-vim3l-board.html">how to dump the S905D3 bootrom</a>.  The guide utilizes a mini Bl2 bootloader script that can be loaded with Amlogic's update tool to dump the bootrom code over UART.  However, running the script requires executing code in secure world, which is not possible with secure boot enabled on the Cube. Instead we need a device like Khadas' VIM3L that has secure boot disabled, but with an S922X SOC like Hardkernel's Odroid N2+. With the Odroid N2+, we follow the S905D3 guide to a tee, only using the <code>aml_encrypt_g12b tool</code>, rather than the <code>aml_encrypt_g12b</code> during the build process.  

#### Build bootrom dumper 
The code is built using GNU C cross-compiler for the arm64 architecture (packages gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu on Debian) :

<code>sudo aarch64-linux-gnu-gcc -O3 -nostdlib -Wl,--build-id=none -o S922X_dump_bootrom.elf S922X_dump_bootrom.c</code><br>
<code>sudo aarch64-linux-gnu-objcopy -O binary -j .text S922X_dump_bootrom.elf S922X_dump_bootrom.bin</code>

Then, the binary is packaged as regular BL2 image for this target using the aml_encrypt_g12a tool from khadas-uboot repository:

<code>sudo ./khadas-uboot/fip/g12b/aml_encrypt_g12b --bl2sig --input ./S922X_dump_bootrom.bin --</code>

### Updating amlogic-usbdl & payloads
To determine whether the S922X is vulnerable to Frederic's exploit we attempt to re-extract the bootrom, but this time using the <code>amlogic-usbdl</code> exploit tool.  <code>Amlogic-usbdl</code> is used attempt to execute unsigned code with instructions to dump the bootrom to UART.  The unsigned code is contained in the <code>amlogic-usbdl</code> payload <code>dump_bootrom_uart_s922x.S</code>, but first we need to update the payload which was written for the S905D3, with the <a href="https://github.com/Pro-me3us/amlogic-usbdl_S922X/commit/49b360360888de96e81e1dfe206e0864e91d4000">UART hardware address</a> for the S922X:

<code>
_uart_putc: .dword 0xffff25f4
</code>
<br><br>

Next, we have to find an address for the download buffer pointer (<code>TARGET_RA_PTR</code>) within the <code>0xFFFE3600-0xFFFE3800</code> stack buffer range that will work with the S922X.  After trying a long list of addresses within the stack buffer without success, we discover that by modifying the <code>bulk_transfer_size</code> in addition to <code>TARGET_RA_PTR</code> we are finally able to get some UART output.  Analysis of the UART output confirms it is the bootrom code, and that the USB stack buffer bug was present in the S922X as well.  In testings, the <code>bulk_transfer_size</code> could be decreased to as little as <code>0x6</code>, increasing the maximum payload size to 65530 bytes. We settle on <code>0xFE</code> for the <code>bulk_transfer_size</code> to keep things similar to the S905D3 exploit for simplicity, and <code>0xFFFE3678</code> for the <a href="https://github.com/Pro-me3us/amlogic-usbdl_S922X/commit/20d7b89d16360266f7cb182eac709ddd0724dd8f">buffer pointer address</a>.

### Bootloader decryption
Knowing that the download buffer bug is replicable on the Cube, we obtain the Cube bootloader image (7.2.7.3/2625) from the FireTV OTA update bin, so that it can be modified to give us unrestricted access to the device.  OTA updates come with a signed and unsigned bootloader.  The unsigned bootloader will not boot on a device with verify boot enabled in the bootrom, which is every consumer Cube.  Presumably this unsigned bootloader is for non-secure Cubes provided to developers by Amazon.  Instead we narrow our focus on the signed bootloader (<code>u-boot.bin.signed</code>). 

The signed bootloaders are encrypted, and we need to decrypt it in order to make any edits.  Frederic had previously found an AES-256-CBC key in SRAM <code>0xFFFE0020</code> to decrypt the Chromecast bootloader.  To check this address on the Cube, we <a href="https://github.com/Pro-me3us/amlogic-usbdl_S922X/commit/c23b81543c10eb7627b099f5b4767f037a18b8c8">update the memdump_over_usb.c payload</a> to dump SRAM.  There is no key at <code>0xFFFE0020</code> but with further analysis a key is discovered further down at <code>0xFFFE7C20</code>!  Surprisingly, the AES key only decrypts Bl2 & Bl30, and we needed to keep searching for another key to decrypt the rest of the bootloader.  Making the assumption that the key has to either be in the SOC or the decrypted portion of bootloader, three more AES keys are discovered in the decrypted Bl30 code at <code>0x1061C</code>, <code>0x10A84</code>, and <code>0x10EEC</code> (again at <code>0x11354</code>) that  each decrypt a different segment of the signed bootloader.  In addition to the three AES keys, we also find a fourth 48 byte string and potential AES-256-CBC key that we were unable to determine the purpose of.

AES key locations for decrypting the bootloader<br><br>

[SRAM]<br>
1) <code>0xFFFE0020</code> - decrypts Bl2 + Bl30<br><br>

[Bootloader Bl30]<br>
2) <code>0x1061C</code><br>
3) <code>0x10A84</code><br>
4) <code>0x10EEC</code> and <code>0x11354</code><br>
5) <code>0x101b4</code> unknown 48byte value, potential 5th AES key<br>


### Creating a patched Bl2 payload
With the signed bootloader decrypted, Bl2 can now be edited to remove verification checks on the later bootloader stages.  Bl2 is the first 65536 bytes of the bootloader (<code>u-boot.bin.signed</code>), and the last few hundred bytes of that is just padding (0's) added to meet the 65k size requirement.  We crop off the first 65280 bytes of the bootloader which contains on the Bl2 code, and keeps the code size small enough to fit the 65280 byte max payload limit of <code>amlogic-usbdl</code>.

<code>sudo dd if=u-boot.bin.signed of=bl2.bin bs=1 count=65280 skip=0</code>

The trimmed Bl2.bin is then edited in disassembly, patching out a serious of signature checks that verifies the rest of the bootloader.

--- [Bl2.bin]
+++ [Bl2.patched.bin]
```
-00008de0 60 ca 41 79     ldrh       w0,[x19, #0xe4]=>DAT_0001136c
-00008de4 01 04 00 51     sub        w1,w0,#0x1
-00008de8 61 ca 01 79     strh       w1,[x19, #0xe4]=>DAT_0001136c
-00008dec c0 00 00 34     cbz        w0,LAB_00008e04
-00008df0 20 00 00 b0     adrp       x0,0xd000
-00008df4 00 60 2b 91     add        x0=>s_FIP_hdr_check_fail,_retry!_0000dad8,x0,#
-00008df8 86 0e 00 94     bl         FUN_0000c810
-00008dfc 20 00 82 52     mov        w0,#0x1001
-00008e00 16 00 00 14     b          LAB_00008e58      
+00008de0 00 00 80 52     mov        w0,#0x0
+00008de4 1f 20 03 d5     nop
+00008de8 1f 20 03 d5     nop
+00008dec c0 00 00 34     cbz        w0,LAB_00008e04
+00008df0 1f 20 03 d5     nop
+00008df4 1f 20 03 d5     nop
+00008df8 1f 20 03 d5     nop
+00008dfc 1f 20 03 d5     nop
+00008e00 1f 20 03 d5     nop

       
-00008ffc 20 00 00 b0     adrp       x0,0xd000
-00009000 00 dc 2e 91     add        x0=>s_DDR_fip_hdr_check_fail,_retry!_0000dbb7,
-00009004 03 0e 00 94     bl         FUN_0000c810                                  
-00009008 a0 00 82 52     mov        w0,#0x1005
-0000900c 93 ff ff 17     b          LAB_00008e58 
+00008ffc 00 00 80 52     mov        w0,#0x0
+00009000 1f 20 03 d5     nop
+00009004 1f 20 03 d5     nop
+00009008 1f 20 03 d5     nop
+0000900c 1f 20 03 d5     nop


-0000bbcc 9c 02 00 94     bl         FUN_0000c63c
+0000bbcc 00 00 80 52     mov        w0,#0x0
```

### Patching and Compiling U-Boot
With the signature checks removed from Bl2.bin, we are now free to make edits to Bl33/U-Boot where Amazon has placed all the device restrictions.  Moving forward there are two possible paths for editing U-Boot 1) either continue to edit the bootloader obtained from the OTA update in disassembly or 2) use Amazon's <a href="https://www.amazon.com/gp/help/customer/display.html?nodeId=201452680">GPL library</a> to edit and compile our own U-Boot image and insert that into the signed bootloader image.  Analyzing the bootloader we find that U-Boot is LZ4 compressed with a custom U-Boot header, and that it can't be decompressed with the standard LZ4 program. Rather than try to reconstruct the standard LZ4 header to decompress the code, we decide to take the easier path and use the GPL repository to compile our own U-Boot image.

While attempting to use Amazon's bootloader compiler we quickly find out that it's broken.  Testing various versions it's determined that <a href="https://fireos-tv-src.s3.amazonaws.com/JnV5RT1byYZhsDAFQ0MuCECV5q/FireTVCubeGen2-7.2.2.9-20201118.tar.bz2">FireTVCubeGen2-7.2.2.9-20201118.tar.bz2</a> is the last version that will fully compile, but because the fastboot boot function is broken, we have to go all the way back to the release build <a href="https://fireos-tv-src.s3.amazonaws.com/YbHeBIPhSWxBTpng8Y0nLiquDC/FireTVCubeGen2-7.2.0.4-20191004.tar.bz2">FireTVCubeGen2-7.2.0.4-20191004.tar.bz2</a>.

The 2nd Gen Cube is actually shipped with an unlocked bootloader, and it's Amazon's included security layer that applies all the user restrictions.  Several files in the bootloader source are edited to remove restrictions on the U-Boot and fastboot commandlines, and have our Cube classified as an 'engineering device' for greater freedom.  The newly compiled U-Boot/Bl33 image is then merged into the signed bootloader.  The details of the bootloader edits, compilation, and merging can be found here:

https://github.com/Pro-me3us/Raven_Bootloader_Builder/


### Booting the modified bootloader
With both a patched Bl2 image to use as a payload for amlogic-usbdl, and bootloader image with Bl33/U-Boot patched to remove all user restrictions, it's time load them together. 

1) Boot the patched Bl2 image<br>
```sudo ./amlogic-usbdl bl2.bin```

2) Continue the bootup proccess by loading the rest of the patched bootloader<br>
```sudo ./update bl2_boot bootloader.img```







