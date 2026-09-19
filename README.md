# DirtyInit
One-touch, universal root for Samsung devices as u:r:init:s0 using DirtyFrag

**SUMMARY**

This is the first public DirtyFrag for Android exploit that jumps straight from a user app to root. The root namespace is init - the most powerful non-kernel namespace on Android. It requires no setup or configuration. Best of all, it works for everyone. It's been tested on Galaxy devices from the Note 20 Ultra to the S26 Ultra. 

DirtyInit differs from the @LSPosed team's and @polygraphe's excellent DirtyFrag exploits in two ways:

1) It uses a stable, public API - IpSecManager - to handle the required XFRM socket and crypto. It's the same set of APIs that VPNs and other secure networking apps use. How does this avoid the need for CAP_SYS_ADMIN and a Phase 1 escalation to system_server or network_stack? Because system_server *itself* runs these APIs in its own namespace and forwards them on to the appropriate native networking daemon. Same principle as using a file explorer to install an app - system_server proxies it to installd.
2) It doesn't use DirtyFrag as a step into GhostLock or kernel-root: init is its target. To achieve this escalation, DirtyFrag overwrites the LogMessage function in /system/lib64/libbase.so, which init uses for its logging functions and calls nearly constantly, with a payload that causes init to fork a child and set up a unix stream socket. Init Unix stream sockets are accessible to every namespace except untrusted_app, so we have to use ADB as a relay. 

Once the exploit finishes, tap EXTRACT CLI, which dumps the 'dirtyinit' binary to /sdcard. Then use ADB to copy it to /data/local/tmp and execute it to connect to the init socket and run commands from init's namespace.

**IMPORTANT**

DirtyInit does *NOT* get a true shell as init, and init cannot execute **ANY BINARIES ITSELF**. It has ZERO 'execute_no_trans' selinux file permissions. You cannot place your own custom busybox somewhere and have init execute it in its namespace.

So what happens if you do try to execute something as init? Init immediately does a type_transition to whatever the selinux domain is of what you're trying to execute. It loses all the power that comes from its namespace, *and it can never transition back to init*. That means that the unix stream socket is now owned by whatever domain the init child transitioned to - you can't get back to root.

To mitigate this risk, I tried (not very well) to implement a safer domain transitioning function called 'dexec' in the dirtyinit binary, where it catches an attempted execution and either forks again into a grandchild (so that the original init child and socket remain available) that then tries to type_transition into whatever you're trying to execute, or bails out. It's clunky, ugly, and "60% of the time it works... every time". Use at your own risk.

**OverlayFS**

dirtyinit can also do a basic filesystem overlay using a "dirty" implementation of AOSP's OverlayFS, described at https://android.googlesource.com/platform/system/core/+/master/fs_mgr/README.overlayfs.md. DirtyInit does *NOT* do adb remount, adb root, or any of that. But it uses the underlying architecture, which Samsung left in place in OneUI, but with no Java entrypoint and selinux blocking it for everything but vold and init. It's not a perfect implementation, and you need to be ready to do a whole lot of command line 'chcon' and 'chown' commands to get it working. It's very much YMMV. I started working on this thinking it would be a clever way to load a custom kernel module and get selinux permissive. But when you overlay files on any of the super partitions, those files have the initial domain of 'u:object_r:overlayfs_file:s0', and while init can chcon on just about anything, it can't change something to 'vendor_file' or 'system_file', which is necessary for vendor_modprobe to load it into the kernel.

I haven't actually worked on this functionality for about a month, once I realized I couldn't find a path to kernel module loading with it. But it's still in here, and if anyone has any ideas for other cool stuff to do with it, have at it!
