#!/usr/bin/env python2.7

import sys
import os
import shutil
import zipfile
import re

sys.path.append('cuckoo-headless')
import extract_raw.dump2file as dump2file
from bson_parser.windows import *

# Determines if File I/O and Registry I/O in seq1 are a proper subset of seq2
# API call categories retrieved from: https://github.com/evandowning/monitor/tree/extending-api/sigs/modeling
def eval_io(seq1, seq2):
    api_file = list()
    api_registry = list()

    # Get file api calls
    with open('api_file.txt','r') as fr:
        for line in fr:
            line = line.strip('\n')
            if line[-1] != 'A':
                api_file.append(line+'A')
            if line[-1] != 'W':
                api_file.append(line+'W')

    # Get registry api calls
    with open('api_registry.txt','r') as fr:
        for line in fr:
            line = line.strip('\n')
            if line[-1] != 'A':
                api_registry.append(line+'A')
            if line[-1] != 'W':
                api_registry.append(line+'W')

    seq1_file = list()
    seq1_registry = list()

    seq2_file = list()
    seq2_registry = list()

    # Extract File I/O & Registry I/O from "before" sequence
    for k,v in seq1.items():
        for e in v:
            call = e['api']

            if call in api_file:
                seq1_file.append(e)
            elif call in api_registry:
                seq1_registry.append(e)

    # Extract File I/O & Registry I/O from "after" sequence
    for k,v in seq2.items():
        for e in v:
            call = e['api']

            if call in api_file:
                seq2_file.append(e)
            elif call in api_registry:
                seq2_registry.append(e)


    seq1_file_io = list()
    seq2_file_io = list()

    # Compare File I/O
    for e in seq1_file:
        io = [k for k,v in e['arguments'].items() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])
        seq1_file_io.append(key)

    for e in seq2_file:
        io = [k for k,v in e['arguments'].items() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])

        if key in seq1_file_io:
            seq1_file_io.remove(key)
        else:
            seq2_file_io.append(key)

    # Print result
    sys.stdout.write('File I/O results: ("after" should have all api calls from "before")\n')
    sys.stdout.write('# of files in "after" which are NOT in "before": {0}\n'.format(len(seq2_file_io)))
    sys.stdout.write('# of files in "before" which are NOT in "after" (should be 0): {0}\n'.format(len(seq1_file_io)))
    sys.stdout.write('\n')

    seq1_registry_io = list()
    seq2_registry_io = list()

    #TODO - Parse for registry key value arguments. Is this complete?
    # Compare Registry I/O
    for e in seq1_registry:
        io = [k for k,v in e['arguments'].items() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])
        seq1_registry_io.append(key)

    for e in seq2_registry:
        io = [k for k,v in e['arguments'].items() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])

        if key in seq1_registry_io:
            seq1_registry_io.remove(key)
        else:
            seq2_registry_io.append(key)

    # Print result
    sys.stdout.write('Registry I/O results: ("after" should have all api calls from "before")\n')
    sys.stdout.write('# of files in "after" which are NOT in "before": {0}\n'.format(len(seq2_registry_io)))
    sys.stdout.write('# of files in "before" which are NOT in "after" (should be 0): {0}\n'.format(len(seq1_registry_io)))
    sys.stdout.write('\n')


# Determines if seq1 is a proper subset of seq2
def eval_seq(seq1, seq2):
    api2 = list()
    api1 = list()

    # Extract API calls from second sequence
    for k,v in sorted(iter(seq2.items()), key=lambda k_v: int(k_v[0])):
        for e in v:
            call = e['api']
            api2.append(call)

    # Extract API calls from first sequence
    for k,v in sorted(iter(seq1.items()), key=lambda k_v1: int(k_v1[0])):
        for e in v:
            call = e['api']

            # If this api call was in api2, remove it from api2
            if call in api2:
                api2.remove(call)
            # Else, add to api1 (i.e., api1 has called an api call not in api2)
            else:
                api1.append(call)

    # Print result
    sys.stdout.write('Sequence results: ("after" should have all api calls from "before")\n')
    sys.stdout.write('# of API calls in "after" which are NOT in "before": {0}\n'.format(len(api2)))
    sys.stdout.write('# of API calls in "before" which are NOT in "after" (should be 0): {0}\n'.format(len(api1)))
    sys.stdout.write('\n')

# Extracts API call sequences from Cuckoo BSON data
def extract_timeline(bsonDir):
    timeline = dict()

    # Get each bson file
    for fn in os.listdir(bsonDir):
        # Ignore our tmp file
        if fn == 'tmp':
            continue

        # We must write the bson data to a temporary file first
        tmpfn = os.path.join(bsonDir,'tmp')

        # Remove temporary file if it already exists
        if os.path.exists(tmpfn):
            os.remove(tmpfn)

        # Extract log contents
        with open(os.path.join(bsonDir,fn), 'rb') as fr:
            for line in fr:
                if 'BSON\n' == line:
                    continue

                if 'BSON\n' in line:
                    line = line[:-5]

                with open(tmpfn,'ab') as fa:
                    fa.write(line)

        # If nothing was parsed, continue
        if not os.path.exists(tmpfn):
            continue

        mon = WindowsMonitor()
        mon.matched = True

        # Parse BSON file
        rv = mon.parse(tmpfn)

        # Extract data
        for e in rv:
            if 'api' in e:
                api = e['api']
                pc = e['eip']
                ts = str(e['time'])

                if ts not in timeline:
                    timeline[ts] = list()
                timeline[ts].append(e)

        # Remove temporary BSON file
        os.remove(tmpfn)

    return timeline

# Extracts API calls from raw Cuckoo logs
def extract(dump_fn):
    # Get folder
    out_base = os.path.join('/tmp','cuckoo-headless-dump',dump_fn)
    if not os.path.exists(out_base):
        os.makedirs(out_base)

    # Dump file contents
    dump2file.dump(dump_fn,out_base)

    # Uncompress zip file
    # From: https://stackoverflow.com/questions/3451111/unzipping-files-in-python
    zippath = os.path.join(out_base,'stuff.zip')
    with zipfile.ZipFile(zippath,'r') as zip_ref:
        zip_ref.extractall(out_base)

    # Parse bson files and extract data
    timeline = extract_timeline(os.path.join(out_base,'logs'))

    # Clean up files
    for fn in os.listdir(out_base):
        path = os.path.join(out_base,fn)

        # If directory
        if os.path.isdir(path):
            shutil.rmtree(path)
        # If file
        else:
            os.remove(path)

    # Remove base tmp directory
    shutil.rmtree(out_base)

    return timeline

def usage():
    sys.stdout.write('usage: python diff.py sysdump_before sysdump_after\n')
    sys.exit(2)

def _main():
    if len(sys.argv) != 3:
        usage()

    dump_before = sys.argv[1]
    dump_after = sys.argv[2]

    # Extract API calls
    api_before = extract(dump_before)
    api_after = extract(dump_after)

    # Evaluate sequence
    eval_seq(api_before,api_after)

    # Evaluate File I/O and Registry I/O
    eval_io(api_before,api_after)

if __name__ == '__main__':
    _main()
