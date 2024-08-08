volatility usage

```
vol -f oceans.raw windows.info
vol -f oceans.raw -p Win7SP1x64 windows.pslist.PsList
vol -f oceans.raw -p Win7SP1x64 windows.psscan.PsScan
vol -f oceans.raw -p Win7SP1x64 windows.pstree.PsTree
vol -f oceans.raw -p Win7SP1x64 windows.psscan.PsScan
vol -f oceans.raw -p Win7SP1x64 windows.pstree.PsTree
vol -f oceans.raw -p Win7SP1x64 windows.dumpfiles.DumpFiles --pid 1804
vol -f memory.raw -p Win7SP1x64 windows.netscan.NetScan
vol -f oceans.raw -p Win7SP1x64 windows.cmdline.CmdLine
vol -f oceans.raw -p Win7SP1x64 windows.getsids.GetSIDs
vol -f oceans.raw -p Win7SP1x64 windows.dumpfiles.DumpFiles --pid 1804
vol -f oceans.raw -p Win7SP1x64 windows.dumpfiles.DumpFiles --pid 1552
vol -f oceans.raw -p Win7SP1x64 windows.registry.hivelist.HiveList
vol -f oceans.raw -p Win7SP1x64  windows.registry.userassist.UserAssist

python2.7 volatility/vol.py -f oceans.raw --profile Win7SP1x64 procdump -p 1552 --dump-dir ./dump
```