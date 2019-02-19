import sys
import os
import shutil
import zipfile

import dump2file
from bson_parser.windows import *

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
    print 'Sequence results: (before should have all api calls in after)'
    print '# of API calls in after which are NOT in before: {0}'.format(len(api2))
    print '# of API calls in before which are NOT in after: {0}'.format(len(api1))

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

    #TODO
    # Evaluate File I/O and Registry I/O

if __name__ == '__main__':
    _main()
