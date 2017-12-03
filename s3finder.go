// s3finder finds S3 buckets
package main

/*
 * s3finder.go
 * Find s3 buckets
 * By J. Stuart McMurray
 * Created 20171202
 * Last Modified 20171202
 */

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	certstream "github.com/CaliDog/certstream-go"
)

const (
	// MAXRECURSION is the maximum number of times we check a single
	// bucket name with different regions.  In practice, there should never
	// be more than two checks, unless someone's bucket moved regions while
	// we're checking it.
	MAXRECURSION = 10

	// S3URL is the base S3 URL to try, with a placeholder for the region
	// and the bucket name.
	S3URL = `https://s3%v.amazonaws.com/%v`
)

func main() {
	var (
		nQuery = flag.Uint(
			"n",
			16,
			"Query at most `N` domains in parallel",
		)
		nameF = flag.String(
			"f",
			"",
			"Name of `file` with one S3 bucket name per line, "+
				"or - to read from stdin",
		)
		watchCerts = flag.Bool(
			"certs",
			false,
			"Watch certificate transparency logs for names",
		)
		nonBuckets = flag.Bool(
			"non-buckets",
			false,
			"Print names which don't have an S3 bucket",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options] [name [name...]]

Tries to find publicly-accessible S3 buckets given bucket names or by watching
the certificate transparency logs.

Names may be read from a file with -f, in which case blank lines and lines
starting with a # will be skipped.  The file name may be - to read from stdin.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Log for successes */
	slog := log.New(os.Stdout, "", log.LstdFlags)

	/* HTTP Client which follows no redirects */
	NRClient := &http.Client{
		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	/* Start checkers */
	wg := &sync.WaitGroup{}
	namech := make(chan string)
	for i := uint(0); i < *nQuery; i++ {
		wg.Add(1)
		go checker(namech, NRClient, wg, slog, *nonBuckets)
	}

	/* Handle names from a file, if we have one */
	if "" != *nameF {
		if err := namesFromFile(namech, *nameF); nil != err {
			log.Printf(
				"Error reading names from %v: %v",
				*nameF,
				err,
			)
		}
	}

	/* Handle names on the command line */
	if 0 < flag.NArg() {
		for _, n := range flag.Args() {
			namech <- n
		}
	}

	/* Handle names from certificate transparency logs */
	if *watchCerts {
		watchLogs(namech)
	}

	close(namech)

	/* Wait for checkers to finish */
	wg.Wait()
	log.Printf("Done.")
}

/* namesFromFile sends the non-comment, non-blank lines of the file named n to
c. */
func namesFromFile(c chan<- string, n string) error {
	f := os.Stdin

	/* Try to open file if we have a name */
	if "-" != n {
		var err error
		f, err = os.Open(n)
		if nil != err {
			return err
		}
		defer f.Close()
	}

	/* Read lines, send to c */
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		/* Skip blank lines and comments */
		if "" == l || strings.HasPrefix(l, "#") {
			continue
		}
		/* Send line to channel */
		c <- l
	}
	if err := scanner.Err(); nil != err {
		return err
	}
	return nil
}

/* watchLogs sends names from certificate transparency logs to namech.  It
returns on error. */
func watchLogs(namech chan<- string) {
	/* Open the cert stream */
	certs, errs := certstream.CertStreamEventStream(true)
	log.Printf("Made certificate stream")
CERTLOOP:
	for {
		select {
		case cert, ok := <-certs: /* Got a new cert */
			if !ok {
				log.Printf("End of certificate stream")
				certs = nil
				break
			}
			/* Pull out domains for which the cert is valid */
			names, err := cert.ArrayOfStrings(
				"data",
				"leaf_cert",
				"all_domains",
			)
			if nil != err {
				log.Printf("Certificate error: %v", err)
				continue
			}
			/* Send them to be checked */
			for _, name := range names {
				/* Don't query for wildcards */
				if strings.Contains(name, "*") {
					continue
				}
				namech <- name
			}
		case err, ok := <-errs: /* Stream error of some sort */
			if !ok {
				log.Printf("End of error stream")
				errs = nil
				break CERTLOOP
			}
			log.Printf("Certificate stream error: %v", err)
		}
	}
}

/* checker checks if the domain names sent on namech are public s3 buckets.
Requests to see if the domain is an S3 bucket are made with c.  If nonBuckets
is true, names which aren't buckets are printed. */
func checker(
	namech <-chan string,
	c *http.Client,
	wg *sync.WaitGroup,
	slog *log.Logger,
	nonBuckets bool,
) {
	defer wg.Done()
	for name := range namech {
		/* Check each name */
		check(name, "", c, MAXRECURSION, slog, nonBuckets)
		/* Check the dots-to-dashes equivalent */
		if d := strings.Replace(name, ".", "-", -1); d != name {
			check(d, "", c, MAXRECURSION, slog, nonBuckets)
		}

	}
}

/* check checks if n is a domain pointing to a publically-accessible s3 bucket,
using c to make requests to see if the bucket is public.  rem controlls how
many recurions remain before we give up.  If nonBuckets is true, names which
aren't buckets are printed. */
func check(
	n string,
	region string,
	c *http.Client,
	rem uint,
	slog *log.Logger,
	nonBuckets bool,
) {
	/* Make sure we're allowed to recurse */
	if 0 == rem {
		log.Printf("[%v] Too many attempts", n)
		return
	}

	/* Make sure the region starts with a -, if needed */
	if "" != region && !strings.HasPrefix(region, "-") {
		region = "-" + region
	}

	/* Check if it's an S3 bucket */
	req, err := http.NewRequest("GET",
		fmt.Sprintf(S3URL, region, n),
		nil,
	)
	if nil != err {
		log.Printf("[%v] Bucket name creates invalid URL: %v", n, err)
		return
	}
	req.Host = n
	res, err := c.Do(req)
	if nil != err {
		log.Printf("[%v] Bucket check error: %v", n, err)
		return
	}
	res.Body.Close()

	/* See what happens */
	switch res.StatusCode {
	case 200: /* Public bucket */
		slog.Printf("[%v] Public bucket: %v", n, req.URL)
	case 307: /* Redirect, it's probably an S3 bucket in another region */
		region := res.Header.Get("x-amz-bucket-region")
		/* We shouldn't be redirected to the default region */
		if "" == region || "us-east-1" == region {
			log.Printf(
				"[%v] Unexpected redirect to %q",
				n,
				res.Header.Get("location"),
			)
		}
		/* Check with new region in URL */
		check(n, region, c, rem-1, slog, nonBuckets)
	case 403: /* Bucket, but forbidden */
		log.Printf("[%v] Forbidden (%v)", n, req.URL)
		return
	case 404: /* Not a bucket */
		if nonBuckets {
			log.Printf("[%v] Not a bucket", n)
		}
		return
	default: /* Response we've not seen before */
		log.Printf(
			"[%v] Unexpected response to bucket check at %v: %v",
			n,
			req.URL,
			res.Status,
		)
		return
	}
}
