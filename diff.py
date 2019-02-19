import sys
import os
import shutil
import zipfile
import re

import dump2file
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
    for k,v in seq1.iteritems():
        for e in v:
            call = e['api']
            print call

            if call in api_file:
                seq1_file.append(e)
            elif call in api_registry:
                seq1_registry.append(e)

    # Extract File I/O & Registry I/O from "after" sequence
    for k,v in seq2.iteritems():
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
        io = [k for k,v in e['arguments'].iteritems() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])
        seq1_file_io.append(key)

    for e in seq2_file:
        io = [k for k,v in e['arguments'].iteritems() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])

        if key in seq1_file_io:
            seq1_file_io.remove(key)
        else:
            seq2_file_io.append(key)

    # Print result
    print 'File I/O results: ("before" should have all api calls in "after")'
    print '# of files in "after" which are NOT in "before": {0}'.format(len(seq2_file_io))
    print '# of files in "before" which are NOT in "after": {0}'.format(len(seq1_file_io))
    print ''

    seq1_registry_io = list()
    seq2_registry_io = list()

    #TODO - Parse for registry key value arguments
    # Compare Registry I/O
    for e in seq1_registry:
        print e
        io = [k for k,v in e['arguments'].iteritems() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])
        seq1_registry_io.append(key)

    for e in seq2_registry:
        print e
        io = [k for k,v in e['arguments'].iteritems() if re.match(r'.*FileName.*', k) is not None]
        key = e['api'] + ' ' + str([e['arguments'][k] for k in io])

        if key in seq1_registry_io:
            seq1_registry_io.remove(key)
        else:
            seq2_registry_io.append(key)

    # Print result
    print 'Registry I/O results: ("before" should have all api calls in "after")'
    print '# of files in "after" which are NOT in "before": {0}'.format(len(seq2_registry_io))
    print '# of files in "before" which are NOT in "after": {0}'.format(len(seq1_registry_io))
    print ''


# Determines if seq1 is a proper subset of seq2
def eval_seq(seq1, seq2):
    api2 = list()
    api1 = list()

    # Extract API calls from second sequence
    for k,v in sorted(seq2.iteritems(), key=lambda (k,v): int(k)):
        for e in v:
            call = e['api']
            api2.append(call)

    # Extract API calls from first sequence
    for k,v in sorted(seq1.iteritems(), key=lambda (k,v): int(k)):
        for e in v:
            call = e['api']

            # If this api call was in api2, remove it from api2
            if call in api2:
                api2.remove(call)
            # Else, add to api1 (i.e., api1 has called an api call not in api2)
            else:
                api1.append(call)

    # Print result
    print 'Sequence results: ("before" should have all api calls in "after")'
    print '# of API calls in "after" which are NOT in "before": {0}'.format(len(api2))
    print '# of API calls in "before" which are NOT in "after": {0}'.format(len(api1))
    print ''

# Extracts API calls from raw Cuckoo logs
def extract(dump_fn):
    # Dump file contents
    dump2file.dump(dump_fn)

    # Uncompress zip file
    with zipfile.ZipFile('stuff.zip','r') as zip_ref:
        zip_ref.extractall('stuff')

    timeline = dict()

    bsonDir = os.path.join('stuff','logs')

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
                ts = str(e['time'])

                if ts not in timeline:
                    timeline[ts] = list()
                timeline[ts].append(e)

        # Remove temporary BSON file
        os.remove(tmpfn)

    # Clean up files
    shutil.rmtree('stuff')
    os.remove('stuff.zip')

    return timeline

def usage():
    print 'usage: python diff.py sysdump_before sysdump_after'
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
