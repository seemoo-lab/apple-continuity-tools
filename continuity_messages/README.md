# Print Continuity Messages

This folder contains a set of breakpoint commands for the system daemon _rapportd_.
The commands will print the content of all Continuity messages sent over the _Handoff_ or _Universal Clipboard_ interface.

## Usage

Run `lldb` with the following command. `sudo` is optional, but it can be used to get more feedback if something did not work as expected.

```bash
sudo lldb -S packet_breakpoints.txt
```

### Example

This will print a lot of messages if an iPhone is woken up next to your Mac (because they actually synchronize a lot between each other). Here are some shorter examples:

```
(lldb)  po "---------- Sending object --------"
"---------- Sending object --------"


(lldb)  po $arg1
CLinkCnx-321, SMsg, ID xxxxxxxxxx, IDS 'xxxxxxxxxx', Nm '😎', Md 'iPhone13,1', LT Enet, PV-RPI


(lldb)  po $arg3
com.apple.coreduet.fetch-source-device-id


(lldb)  po $arg4
{
    client = "xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx";
    version = "3.0";
}


(lldb)  bt
* thread #1, queue = 'CUMainQueue', stop reason = breakpoint 2.1
  * frame #0: 0x00007fff615ec860 Rapport`-[RPConnection _receivedObject:ctx:]
    frame #1: 0x00007fff615ec70e Rapport`-[RPConnection _receivedHeader:encryptedObjectData:ctx:] + 258
    frame #2: 0x00007fff615ec119 Rapport`-[RPConnection _receivedHeader:body:ctx:] + 474
    frame #3: 0x00007fff615ebdcf Rapport`-[RPConnection _receiveCompletion:] + 579
    frame #4: 0x00007fff4f3a458e CoreUtils`-[CUTCPConnection _completeReadRequest:error:] + 190
    frame #5: 0x00007fff4f3a3bb3 CoreUtils`-[CUTCPConnection _processReads:] + 532
    frame #6: 0x00007fff6f7cc6c4 libdispatch.dylib`_dispatch_call_block_and_release + 12
    frame #7: 0x00007fff6f7cd658 libdispatch.dylib`_dispatch_client_callout + 8
    frame #8: 0x00007fff6f7d2c44 libdispatch.dylib`_dispatch_lane_serial_drain + 597
    frame #9: 0x00007fff6f7d3609 libdispatch.dylib`_dispatch_lane_invoke + 414
    frame #10: 0x00007fff6f7d8b6d libdispatch.dylib`_dispatch_main_queue_callback_4CF + 618
    frame #11: 0x00007fff357aee81 CoreFoundation`__CFRUNLOOP_IS_SERVICING_THE_MAIN_DISPATCH_QUEUE__ + 9
    frame #12: 0x00007fff3576ec87 CoreFoundation`__CFRunLoopRun + 2028
    frame #13: 0x00007fff3576de3e CoreFoundation`CFRunLoopRunSpecific + 462
    frame #14: 0x00007fff37e091c8 Foundation`-[NSRunLoop(NSRunLoop) runMode:beforeDate:] + 212
    frame #15: 0x00007fff37ebbc6f Foundation`-[NSRunLoop(NSRunLoop) run] + 76
    frame #16: 0x0000000105e3a0ab rapportd`___lldb_unnamed_symbol477$$rapportd + 737
    frame #17: 0x00007fff6f826cc9 libdyld.dylib`start + 1
    frame #18: 0x00007fff6f826cc9 libdyld.dylib`start + 1

(lldb)  po "---------- Received object --------"
"---------- Received object --------"


(lldb)  po $arg1
CLinkCnx-321, SMsg, ID xxxxxxxxx, IDS 'xxxxxxxx', Nm '😎', Md 'iPhone13,1', LT Enet, PV-RPI


(lldb)  po $arg3
{
    "_c" =     {
        result =         {
            deviceID = "xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx";
        };
        server = "xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx";
        version = "3.0";
    };
    "_t" = 3;
    "_x" = xxxxxxxxxxx;
}


(lldb)  po $arg4
xxxxxxxxxxxxxx


```
