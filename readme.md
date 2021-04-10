# pySigMaker

An IDA Pro plugin to make creating code signatures quick and simple.  This is a 
port of the popular (compiled) version of SigMaker-X64 with a new pyQt5 GUI that can
be left open as a floating window or docked.  The primary goal was to make a plugin 
that would work with many versions of IDA without needing to compile against the IDA SDK.
Since the IDAPython API is now uniform in structure it seemed like a good time to tackle
this project.

Ported by:  [zoomgod](https://www.unknowncheats.me/forum/members/146787.html)

[Credits to the author/contributors of SigMaker-x64 for the core sig generating code.](https://github.com/ajkhoury/SigMaker-x64)

** Requires Python 3.5 or newer, tested with 3.8 **

IDA Pro version: Need feedback but oldest for sure would be IDA Pro 6.9.

### Install:
    copy pySigMaker.py into IDA plugin folder.

    **Note** Default is to use same hotkey as SigMaker-x64 (Ctrl-Alt-S) which will 
             cause a warning to be displayed in IDA if orig SigMaker-x64 plugin 
             exists.  On settings tab there will be an option to archive the origional
             SigMaker-X64 plugins to a folder in IDA plugins dir.  Or you can 
             choose to change the hotkey.  This plugin will get priority if both exist
             and default hotkey is used.

### Default hotkey:
 - Ctrl + Alt + S

### Feedback needed:
	Report IDA Pro, IDAPython and Python versions this worked on.

### Confirmed working:
	IDA Pro 7.5, IDAPython 64-bit v7.4.0 final, Python 3.8 64 bit

### Sig types supported:
	IDA Patterns : E8 ? ? ? ? 48 8B 83 ? ? ? ? 48 8B CB
    Olly Patterns: E8 ?? ?? ?? ?? 48 8B 83 ?? ?? ?? ?? 48 8B CB
    Code Patterns: \xE8\x00\x00\x00\x00\x48\x8B x????xx (mask optional)

### Bug fixes:
    Fixed issue with rebased images (related to ida inf struct)

### Not ported:
    1. The crc signature portion was dropped.

### Changes:
    1. Making a sig from selection was replaced with an auto-create at current address. 
    2. Trailing wildcards on sigs are dropped
    3. Added a new pyQt5 tabbed Gui that can be used in floating or docked modes.
    4. LOG_ERROR is minimum output setting now so error messages are always output.
    5. Improved history, mask automatically restored based on sig selected in drop down.

### Images:
   
![Create Sigs Tab](https://i.imgur.com/dPWPn0Y.png)
   
![Test Sigs Tab](https://i.imgur.com/qsa4QmS.png)

![Settings Tab](https://i.imgur.com/Ngp7Sa5.png)

![Floating mode](https://i.imgur.com/QLggNlG.png)

![Docked](https://i.imgur.com/44BLrfS.png)
