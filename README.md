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

CTL Subdomains
--------------
Additional subdomains of a given domain can be found from the certificate
transparency logs with `-ctl`.  This causes a considerably longer runtime but
greatly expands the number of buckets which will be searched.  Another downside
is that as subdomains are searched without parent domains (e.g.
`foo.bar.tridge.com` will cause `foo.bar` and `foo` to be searched), a lot of
open buckets for common names are found.  Even still, using `-ctl` greatly
increases the chance of finding relevant buckets.

Tags
----
As it's fairly common for buckets to be something other than just a domain
name, S3Finder can add tags like "backup" or "images" to queried names.  Thus,
for `foo.example.com`, `backup-foo.example.com`, `foo-example-com-images`, and
a handful of other combinations will be tried.  A comprehensive list is
built-in to S3Finder, but a custom list can be specified with `-tags`.  Tags
can be disabled with `-tags no`.

All of the buckets which would be searched for `division.example.com` using
the built-in list are in the file
[`division.example.com_buckets`](division.example.com_buckets).
