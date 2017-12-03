S3Finder
========
Yet another program to find readable S3 buckets.

Can search using a wordlist or by monitoring the certstream network for
domain names from certificate transparency logs.

Found buckets will be written to stdout.  All other messages are written to
stderr, to make for easy logging.

Heavily influenced by https://github.com/eth0izzle/bucket-stream.

Installation
------------
```
go get -u -v github.com/magisterquis/s3finder
```

Usage
-----
Bucket names can be specified on the command line or in a file with one name
per line.

To search for four buckets named after some stooges:
```bash
cat <<_eof >names
curl
moe
larry
_eof
s3finder -f names shemp
```

Please run s3finder with `-h` for a complete list of options.

CTL Stream
----------
Instead of checking a static list of names, the certificate tranpsarency logs
may be streamed from the certstream network with `-certs`.  The domain names in
the streamed certificates will be checked as bucket names.  This can be
combined with a file and names on the command line.

```bash
s3finder -f possible_names -certs kitten mug tea
```
