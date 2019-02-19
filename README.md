# cuckoo-diff
Determines similarities between malware runs (making sure malware is still malware after modification)

Cuckoo files should be raw logs from my version of Cuckoo & Nvmtrace: https://github.com/evandowning/nvmtrace/tree/kvm

## Usage
```
$ python diff.py sysdump_before sysdump_after
```
