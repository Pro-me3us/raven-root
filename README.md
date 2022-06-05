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

#### Build
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

### Bootloader decryption
Knowing that the we could replicate the download buffer bug on the Cube, we then needed to get a copy of the Bl2 code to edit for our exploit.  Bl2 is the first 65kb of the bootloader image, so we extracted the signed bootloader from one of the OTA updates.  The signed bootloaders are encrypted, and we would need to decrypt it in order to edit it.  Frederic had previously found an AES-256-CBC key in SRAM 0xFFFE0020 to decrypt the Chromecast bootloader.  We <a href="https://github.com/Pro-me3us/amlogic-usbdl_S922X/commit/c23b81543c10eb7627b099f5b4767f037a18b8c8">updated the memdump_over_usb.c payload</a> to dump SRAM.  There was no key at 0xFFFE0020 but with further analysis, we found the key further down at <code>0xFFFE7C20</code>.  However, the AES key only decrypted Bl2 & Bl30, and we needed to keep searching for another key.  Making the assumption that the key had to either be in the SOC or the decrypted portion of bootloader, we eventually found three AES keys in Bl30 at <code>0x1061C</code>, <code>0x10A84</code>, and <code>0x10EEC</code> (again at <code>0x11354</code>).  In addition to the three AES keys for the bootloader, we also found a fourth 48 byte string and potential AES-256-CBC key that we were unable to determine the purpose of.


The OTA updates include two bootloaders, u-boot.bin and u-boot.bin.signed. The unsigned u-boot.bin is also not encrypted, and will not load on a production Cube.  The unsigned bootloader has not been changed since the release of the Cube, and may be specifically for developer units provided by Amazon that don't have the boot verify and boot encrypt efuses burned in the SOC.  The AES key

### Creating a patched Bl2 payload
The first 65536 bytes of the bootloader (u-boot.bin.signed) is Bl2, of which the last several hundred bytes being padding added during the signing process. The first 65280 bytes of the bootloader was trimmed from the bootloader, removing some of that padding to fit the 65280 byte payload limit of amlogic-usbdl.
<code>sudo dd if=u-boot.bin.signed of=bl2.bin bs=1 count=65280 skip=0</code>

The decrypted, trimmed Bl2.bin was then edited in disassembly, patching out a serious of signature checks that verifies the rest of the bootloader.

--- <Bl2.bin>
+++ <Bl2.patched.bin>
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
With the signature checks removed from Bl2.bin, we were now free to make edits to Bl33/U-Boot.  We had two choices for editing U-Boot, either continue to edit the bootloader obtained from the OTA update in disassembly, or use Amazon's GPL library to edit and compile our own U-Boot image and insert that into our bootloader image.  Analyzing the bootloader we find that U-Boot is LZ4 compressed with a custom U-Boot header, and that we couldn't decompress it with a standard LZ4 program. Rather than try to reconstruct a standard header to decompress the U-Boot, we decided to take the easier path and use Amazon's GPL repository to compile our own U-Boot image.

While attempting to use Amazon's bootloader compiler we quickly find out that it's broken.  Testing various versions we determine that <a href="https://fireos-tv-src.s3.amazonaws.com/JnV5RT1byYZhsDAFQ0MuCECV5q/FireTVCubeGen2-7.2.2.9-20201118.tar.bz2">FireTVCubeGen2-7.2.2.9-20201118.tar.bz2</a> is the last version that will fully compile, but because the fastboot boot function is broken, we had to go all the way back to the release build <a href="https://fireos-tv-src.s3.amazonaws.com/YbHeBIPhSWxBTpng8Y0nLiquDC/FireTVCubeGen2-7.2.0.4-20191004.tar.bz2">FireTVCubeGen2-7.2.0.4-20191004.tar.bz2</a>.

The 2nd Gen Cube is shipped with an unlocked bootloader, and it's an Amazon security layer that applies user restrictions.  We began by removing the restrictions on the U-Boot console applied by amzn_lockdown.c


--- <amzn_lockdown.c orginal>
```
bool amzn_is_command_blocked(const char *cmd)
{
-	int i = 0, found = 0;
-
-	/* Are we in lock down? */
-	if (lockdown_commands == false)
-		return false;
-
-	/* Is this an engineering device? */
-	if (amzn_target_device_type() == AMZN_ENGINEERING_DEVICE)
-		return false;
-
-	/* Are we un-locked? */
-	if (amzn_target_is_unlocked())
-		return false;
-
-	if (amzn_target_is_onetime_unlocked())
-		return false;
-
-	/* If command is on the white-list, allow */
-	for (i = 0; i < ARRAY_SIZE(whitelisted_commands); i++)
-		if (strcmp(whitelisted_commands[i], cmd) == 0)
-			found = 1;
-
-	/* Not on the white-list? Block */
-	if (!found)
-		return true;
-
	return false;
}
```

<amzn_lockdown.c patched>
//moved to top, line 17
```
bool amzn_is_command_blocked(const char *cmd)
{
	return false;
}
```

Next we removed restrictions on fastboot commands

<amzn_fastboot_lockdown.c original>
```
__attribute__((weak)) int is_locked_production_device() {
-#if defined(UFBL_FEATURE_SECURE_BOOT)
-	return (AMZN_PRODUCTION_DEVICE == amzn_target_device_type()) && (1 != g_boot_arg->unlocked);
-#else
	return 0;
-#endif
}

#else /* UFBL_PROJ_ABC */

__attribute__((weak)) int is_locked_production_device() {
#if defined(UFBL_FEATURE_SECURE_BOOT) && defined(UFBL_FEATURE_UNLOCK)
	return (AMZN_PRODUCTION_DEVICE == amzn_target_device_type()
                        && (!amzn_target_is_unlocked())
#if defined(UFBL_FEATURE_TEMP_UNLOCK)
                        && (!amzn_target_is_temp_unlocked())
#endif
#if defined(UFBL_FEATURE_ONETIME_UNLOCK)
                        && (!amzn_target_is_onetime_unlocked())
#endif
			);
#else
	return 0;
#endif
}

#endif /* UFBL_PROJ_ABC */
```

<amzn_fastboot_lockdown.c patched>
```
__attribute__((weak)) int is_locked_production_device() {
    return 0;
}
```
<amzn_fastboot_lockdown.c original>
```
	for (i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); ++i) {
		if (memcmp(buffer, blacklist[i], strlen(blacklist[i])) == 0) {
			return 1;
		}
	}

	amzn_extends_fastboot_blacklist(&list, &length);
	if (list != NULL && length > 0) {
		for (i = 0; i < length; ++i) {
			if (memcmp(buffer, list[i], strlen(list[i])) == 0) {
				return 1;
			}
		}
	}

	return 0;
}
```

<amzn_fastboot_lockdown.c patched>
```
	for (i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); ++i) {
		if (memcmp(buffer, blacklist[i], strlen(blacklist[i])) == 0) {
			return 0;
		}
	}

	amzn_extends_fastboot_blacklist(&list, &length);
	if (list != NULL && length > 0) {
		for (i = 0; i < length; ++i) {
			if (memcmp(buffer, list[i], strlen(list[i])) == 0) {
				return 0;
			}
		}
	}

	return 0;
}
```
Next we remove the fastboot flash image verification check

<image_verify.c original>
``` 
int
amzn_image_verify(const void *image,
		  unsigned char *signature,
		  unsigned int image_size, meta_data_handler handler)
{
	int auth = 0;
	char *digest = NULL;

	if (!(digest = amzn_plat_alloc(SHA256_DIGEST_LENGTH))) {
		dprintf(CRITICAL, "ERROR: Unable to allocate image hash\n");
		goto cleanup;
	}

	memset(digest, 0, SHA256_DIGEST_LENGTH);

	/*
	 * Calculate hash of image for comparison
	 */
	amzn_target_sha256(image, image_size, digest);

	if (amzn_verify_image(AMZN_PRODUCTION_CERT, digest,
					signature, handler)) {
		if (amzn_target_device_type() == AMZN_PRODUCTION_DEVICE) {
			dprintf(ALWAYS,
				"Image FAILED AUTHENTICATION on PRODUCTION device\n");
			/* Failed verification */
			goto cleanup;
		} else {
		        dprintf(ALWAYS,
				"Authentication failed on engineering device with production certificate\n");
		}

		if (amzn_target_device_type() != AMZN_ENGINEERING_DEVICE) {
			dprintf(ALWAYS,
				"%s: Unknown device type!\n", UFBL_STR(__FUNCTION__));
			goto cleanup;
		}

		/* Engineering device */
		if (amzn_verify_image(AMZN_ENGINEERING_CERT, digest,
					signature, handler)) {
			dprintf(ALWAYS,
				"Image FAILED AUTHENTICATION on ENGINEERING device\n");
			goto cleanup;
		}
	} else {
		dprintf(ALWAYS,
			"Image AUTHENTICATED with PRODUCTION certificate\n");
	}

	auth = 1;

cleanup:
	if (digest)
		amzn_plat_free(digest);

	return auth;
}
```

<image_verify.c patched>
```
int
amzn_image_verify(const void *image,
          unsigned char *signature,
          unsigned int image_size, meta_data_handler handler)
{
    return 1;
}
```

We edit secure_boot.c to identify our Cube as an engineering device.  This is a redundancy that should cover any restrictions we may have missed.
Make Cube an engineering device for more privlages
<secure_boot.c original>
```
Original
int amzn_target_device_type(void)
{
	/* Is anti-rollback enabled? */
	if (query_efuse_status("ARB") == 1)
		return AMZN_PRODUCTION_DEVICE;
	else
		return AMZN_ENGINEERING_DEVICE;
}
```

<secure_boot.c original>
```
int amzn_target_device_type(void)
{
	/* Is anti-rollback enabled? */
	if (query_efuse_status("ARB") == 1)
		return AMZN_ENGINEERING_DEVICE;
	else
		return AMZN_ENGINEERING_DEVICE;
}
```
Lastly we edit main.c to boot us into our desired boot mode (fastboot, update / Amlogic burn mode, U-Boot console)
Patch to boot us into the desired mode
<main.c patched>
add to line 147 to boot to fastboot
```
	run_command("fastboot", 0); 
	run_preboot_environment_command();
```
add to line 147 to boot to fastboot
```
	run_command("update", 0); 
	run_preboot_environment_command();
```
To automatically be dropped into the U-Boot console remove the following line
```	
autoboot_command(s);    //comment out to boot to uboot cmdline	
```





