S3Finder
========
Yet another program to find readable S3 buckets.

Can search using a wordlist or by monitoring the certstream network for
domain names from certificate transparency logs.  If a name contains dots, a
name with the dots replaced by dashes will be tried, as well.  All queries are
done via HTTPS.

Found buckets will be written to stdout.  All other messages are written to
stderr, to make for easy logging.

Heavily influenced by https://github.com/eth0izzle/bucket-stream.

*As of Go 1.9.2, there is a bug which causes memory and CPU exhaustion with
international domain names.  This can be triggered by feeding trying a name
with "special" (i.e. non-alphanumeric) characters.  Building with the current
(as of 20171204) Go master branch solves this problem.  Binaries available
upon request.  Please see https://github.com/golang/go/issues/22184 for more
details*

For legal use only.

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
