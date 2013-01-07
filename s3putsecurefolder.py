#!/usr/bin/env python
# Copyright (c) 2009-2012 Steve Streeting

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import sys
import os
import hashlib
import tempfile
import subprocess
import time
from optparse import OptionParser
from boto.s3.connection import S3Connection
from boto.s3.bucket import Bucket
import fnmatch

SRC_MD5_META='s3putsecure-md5'

currentKeyName=''
lastTime=time.time()
lastBytes=0
currentKps=0

def progress(bytes_done, total_bytes):
    global lastBytes, lastTime, currentKps, currentKeyName
    bytediff = bytes_done - lastBytes
    nowTime = time.time()
    timeDiff = nowTime - lastTime
    if timeDiff > 0:
        currentKps = (bytediff / timeDiff) / 1024
        lastBytes = bytes_done
        lastTime = nowTime

    msg = "\rProgress: %s - %d / %d bytes (%d%%) (%dK/s)" % (currentKeyName, bytes_done, total_bytes, (bytes_done * 100) / total_bytes, currentKps)
    sys.stdout.write(msg)
    sys.stdout.flush()
             
# Utility script for uploading the contents of a local folder to an S3 bucket, encrypting
# every file before upload, and only uploading those files which are different locally. The 
# MD5 of every file is used to determine if the local file is different. Local files are
# always uploaded if the MD5 differs regardless of modification time'''
 
# Parse options
parser = OptionParser(usage='usage: %prog [options] source_folder target_bucket gpg_recipient_or_phrase')
parser.add_option('-n', '--dry-run', action='store_true', dest='simulate', default=False, 
                  help='Do not upload any files, just list actions')
parser.add_option('-a', '--accesskey', dest='access_key', 
                  help='AWS access key to use instead of relying on environment variable AWS_ACCESS_KEY')
parser.add_option('-s', '--secretkey', dest='secret_key', 
                  help='AWS secret key to use instead of relying on environment variable AWS_SECRET_KEY')
parser.add_option('-c', '--create', action='store_true', dest='create_bucket', default=False,
                  help='Create bucket if it does not already exist')
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False,
                  help='Verbose output')
parser.add_option('-S', '--symmetric', action='store_true', dest='symmetric', default=False,
                  help='Instead of encrypting with a public key, encrypts files using a symmetric cypher and the passphrase given on the command-line.')
parser.add_option('-D', '--disableencryption', action='store_true', dest='donotencrypt', default=False,
                  help='Do not encrypt before uploading.')
parser.add_option('-X', '--exclude', action='append', type='string', dest='excludes', 
                  help='Exclude file patterns')

(options, args) = parser.parse_args()

# check remaining args
if len(args) < 2:
    parser.error('Expected at least 2 arguments.')
if len(args) < 3 and not options.donotencrypt:
    parser.error('Expected at least 3 arguments for encrypted sync.')

sourceFolder = args[0]
targetBucket = args[1]
if not options.donotencrypt:
    gpgRecipOrPass = args[2]
simulate = options.simulate
accessKey = options.access_key
secretKey = options.secret_key
donotencrypt = options.donotencrypt

if not os.path.exists(sourceFolder):
    parser.error('Error ' + sourceFolder + ' does not exist.')

if accessKey is None:
    accessKey = os.environ.get('AWS_ACCESS_KEY')
    
if accessKey is None:
    parser.error('Error, no AWS_ACCESS_KEY defined, use -a or --accesskey.')
    
if secretKey is None:
    secretKey = os.environ.get('AWS_SECRET_KEY')
    
if secretKey is None:
    parser.error('Error, no AWS_SECRET_KEY defined, use -s or --secretkey.')

if donotencrypt:
    print 'Warning: encryption disabled as requested'

print 'Uploading ' + sourceFolder + ' to s3://' + targetBucket

print 'Establishing connection to S3...'    
conn = S3Connection(accessKey, secretKey)
print 'Connection successful, opening bucket...'
bucket = conn.get_bucket(targetBucket)
if bucket is None:
    if options.create_bucket: 
        print 'Creating bucket ' + targetBucket
        bucket = conn.create_bucket(targetBucket)
    else:
        print 'Error, bucket ' + targetBucket + ' does not exist.'
        exit(-1) 
print 'Bucket opened successfully.'
if options.simulate:
    print 'Simulation mode, not actually uploading data.'

print 'Please be patient, hash calculations can take a few seconds on larger files.'

# standardise path (removes any trailing slash & double slashes)
sourceFolder = os.path.normpath(sourceFolder)
prefixlen = len(sourceFolder) + 1 # length of prefix, including trailing slash
# get contents of folder
for dirpath, dirname, filenames in os.walk(sourceFolder):
    for f in filenames:
        fullpath = dirpath + '/' + f

        # Check exclusions
        excludeThis = False
        if options.excludes is not None:
            for exclude in options.excludes:
                print 'Checking exclude: ' + exclude
                if fnmatch.fnmatch(fullpath, exclude):
                    excludeThis = True
                    break
        if excludeThis:
            continue

        keyname = fullpath[prefixlen:]
        # check whether this key is present already
        key = bucket.get_key(keyname)
        localfile = file(fullpath, 'rb')
        # check MD5
        localmd5sum = hashlib.md5(localfile.read()).hexdigest()  
        if key is not None:
            # key.etag is the md5 as a quoted string
            # however this is the md5 for the encrypted file, we need to compare the unencrypted md5
            # So, we store the md5 of the unencrypted file in metadata
            remotemd5sum = key.get_metadata(SRC_MD5_META) 
            
            if localmd5sum == remotemd5sum:
                if options.verbose:
                    print fullpath + ' md5 matches s3://' \
                        + targetBucket + '/' + keyname + ' (' + localmd5sum + '), not uploading.'
                continue
            else:
                if options.verbose:
                    print fullpath + ' md5 (' + localmd5sum + ') differs from s3://' \
                        + targetBucket + '/' + keyname + ' md5 (' + remotemd5sum + ')'

        else:
            key = bucket.new_key(keyname)
        # If we get here, we upload
        print 'Uploading ' + fullpath + ' as ' + keyname
        if not options.simulate:
            # set metadata BEFORE upload
            key.set_metadata(SRC_MD5_META, localmd5sum)
            if not options.donotencrypt:
                # encrypt first using gpg
                tempfilename = tempfile.gettempdir() + '/' + f
                if options.symmetric:
                    if options.verbose:
                        print 'Symmetrically encrypting ' + fullpath + ' to ' + tempfilename
                    subprocess.check_call(['gpg', '-c', '--no-use-agent', '--yes', \
                                       '--passphrase', gpgRecipOrPass, '-o', tempfilename, \
                                       fullpath])
                else:
                    if options.verbose:
                        print 'Public-key encrypting ' + fullpath + ' to ' + tempfilename + ' for ' + gpgRecipOrPass
                    subprocess.check_call(['gpg', '-e', '-r', gpgRecipOrPass, '--yes', \
                         '-o', tempfilename, fullpath])          
            else:
                tempfilename = fullpath
            # upload, with progress
            currentKeyName = keyname
            lastTime=time.time()
            currentKps = 0
            key.set_contents_from_filename(tempfilename, cb=progress, num_cb=100)
            if not options.donotencrypt:
                os.remove(tempfilename)
            # newline, to clear progress
            print
                            

            
            
            
        
