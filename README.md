# SpicedHam / snapnative

Go research prototype for selected native Snapchat Android protocol paths on Windows x64.

> **Status:** Experimental, incomplete and for educational purposes only.

## Scope

- Janus password-login and Atlas friends protocol code
- APK, signature and native-library verification
- ARM64/JVM runtime bridge for analysed Android code
- Windows DPAPI-protected, account-separated state
- Persistent account-scoped installation identifiers, including `CloudAccountID`
- FULL-snapshot-only friend parsing

The implemented Janus/Atlas endpoints match the analysed native Snapchat paths and reach the server. A live login currently receives `status=16`, `branch=11`:

```text
Snapchat access temporarily disabled
```

The restriction is unresolved. No valid session or friends snapshot has been issued, and no bypass logic is implemented.
