# SpicedHam / snapnative

Go research prototype for selected native Snapchat Android protocol paths on Windows x64.

> **Status:** Experimental, incomplete and for educational purposes only.

## Scope
- Reverse-engineered Snapchat version: **14.26.1.0** (Android, version code `317772`)

- Janus password-login and Atlas friends protocol code
- APK, signature and native-library verification
- ARM64/JVM runtime bridge for analysed Android code
- Windows DPAPI-protected, account-separated state
- Persistent account-scoped installation identifiers
- FULL-snapshot-only friend parsing

The implemented Janus/Atlas endpoints match the analysed native Snapchat paths and reach the server. A live login currently receives `status=16`, `branch=11`:

```text
Snapchat access temporarily disabled
```

As of right now, I was not able to figure out how to bypass this. It would require an actual real iOS or Android device (no emulator).
Try yourself:
`./snapnative.exe -account test friends`
