// s3finder finds S3 buckets
package main

/*
 * s3finder.go
 * Find s3 buckets
 * By J. Stuart McMurray
 * Created 20171202
 * Last Modified 20171224
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
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/net/publicsuffix"
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

	// SEENCACHESIZE is the number of entries in the LRU cache to keep, to
	// prevent duplicate searches for domains with similar parent domains.
	SEENCACHESIZE = 10240
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
		tagFile = flag.String(
			"tags",
			"",
			"If set, use tags from the file named `F` instead of "+
				"the built-in tags, or \"no\" to disable "+
				"tags altogether",
		)
		ignoreNotAllowed = flag.Bool(
			"ignore-forbidden",
			false,
			"Don't print a message when access to a bucket is "+
				"forbidden (HTTP 403)",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options] [name [name...]]

Tries to find publicly-accessible S3 buckets given bucket names or by watching
the certificate transparency logs.  Names which appear to be domain names
will be searched, then broken into components and searched.

Names may be read from a file with -f, in which case blank lines and lines
starting with a # will be skipped.  The file name may be - to read from stdin.

Tags (such as "backup" and "images" can be added to the names automatically
with the -tags option.  By default, a built-in list of tags is used.  A custom
list may be specified as a file with one tag per line.  Blank lines and lines
starting with a # will be skipped.

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

	/* Get tags */
	tags, err := getTags(*tagFile)
	if nil != err {
		log.Fatalf("Unable to get tags from %v: %v", *tagFile, err)
	}
	if 1 == len(tags) {
		log.Printf("Will apply 1 tag to each name")
	} else {
		log.Printf("Will apply %v tags to each name", len(tags))
	}

	/* Start name processor */
	var (
		bucketch = make(chan string)
		namech   = make(chan string)
	)
	/* TODO: Generate tags */
	go processNames(bucketch, namech, tags)

	/* Start checkers */
	wg := &sync.WaitGroup{}
	for i := uint(0); i < *nQuery; i++ {
		wg.Add(1)
		go checker(
			bucketch,
			NRClient,
			wg,
			slog,
			*nonBuckets,
			*ignoreNotAllowed,
		)
	}

	/* Handle names on the command line */
	if 0 < flag.NArg() {
		for _, n := range flag.Args() {
			namech <- n
		}
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
			log.Fatalf("Certificate stream error: %v", err)
		}
	}
}

/* checker checks if the domain names sent on namech are public s3 buckets.
Requests to see if the domain is an S3 bucket are made with c.  If nonBuckets
is true, names which aren't buckets are printed. */
func checker(
	bucketch <-chan string,
	c *http.Client,
	wg *sync.WaitGroup,
	slog *log.Logger,
	nonBuckets bool,
	ignoreNotAllowed bool,
) {
	defer wg.Done()
	for bucket := range bucketch {
		/* Check each name */
		check(
			bucket,
			"",
			c,
			MAXRECURSION,
			slog,
			nonBuckets,
			ignoreNotAllowed,
		)
	}
}

/* check checks if n is a domain pointing to a publically-accessible s3 bucket,
using c to make requests to see if the bucket is public.  rem controlls how
many recurions remain before we give up.  If nonBuckets is true, names which
aren't buckets are printed.  If ignoreNotALlowed is true, HTTP403's are
silently ignored. */
func check(
	n string,
	region string,
	c *http.Client,
	rem uint,
	slog *log.Logger,
	nonBuckets bool,
	ignoreNotAllowed bool,
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
		check(n, region, c, rem-1, slog, nonBuckets, ignoreNotAllowed)
	case 400: /* Bad request */
		log.Printf("[%v] Bad request (%v)", n, req.URL)
		return
	case 403: /* Bucket, but forbidden */
		if !ignoreNotAllowed {
			log.Printf("[%v] Forbidden (%v)", n, req.URL)
		}
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

/* processNames turns the names on namech into a load of possible bucket names
which are sent to bucketch */
func processNames(
	bucketch chan<- string,
	namech <-chan string,
	tags []string,
) {
	defer close(bucketch)

	/* Cache to prevent duplicate checks */
	seen, err := lru.New(SEENCACHESIZE)
	if nil != err {
		log.Fatalf("Unable to make seen name cache: %v", err)
	}

	/* Check each name sent to us, adding interesting bits and paring down
	long domains. */
	for name := range namech {
		/* Skip empty names and names which look like comments. */
		name := strings.TrimSpace(name)
		if "" == name || strings.HasPrefix(name, "#") {
			continue
		}

		/* Names without a dot aren't DNS names, no need to split */
		if !strings.Contains(name, ".") {
			processName(bucketch, seen, name, tags)
			continue
		}

		/* We likely have a domain name (or something like one).
		Process it and all its parents until but not including the
		public suffix. */
		ps, _ := publicsuffix.PublicSuffix(name)

		/* Process the name and its parents */
		for name != ps {
			processName(bucketch, seen, name, tags)
			/* Split leftmost domain off */
			parts := strings.SplitN(name, ".", 2)
			if 2 != len(parts) {
				log.Panicf("unable to get parent of %q", parts)
			}
			/* Process bare label, as well */
			processName(bucketch, seen, parts[0], tags)
			/* Process parent next time */
			name = parts[1]
			if "" == name {
				return
			}
		}
	}
}

/* processName appends and prepends various tags to the name and changes dots
to hyphens.  The resulting names are sent to bucketch. */
func processName(
	bucketch chan<- string,
	seen *lru.Cache,
	name string,
	tags []string,
) {
	/* If we've seen the name, don't try again */
	if _, ok := seen.Get(name); ok {
		return
	}
	/* Note we've seen it, to prevent rechecking */
	seen.Add(name, nil)

	/* Send name, as-is */
	sendWithDotsAndHyphensChanged(bucketch, []string{name})

	/* Add tags, send out */
	for _, tag := range tags {
		sendWithDotsAndHyphensChanged(bucketch, []string{
			tag + name,
			name + tag,
			tag + "." + name,
			name + "." + tag,
			tag + "-" + name,
			name + "-" + tag,
		})
	}
}

/* sendWithDotsAndHyphensChanged sends every string in ns to c with several
combinations of changing dots to dashes and vice-versa.  No duplicates will be
sent. */
func sendWithDotsAndHyphensChanged(c chan<- string, ns []string) {
	m := map[string]struct{}{} /* Deduper */

	/* Add all combinations to m */
	for _, n := range ns {
		/* The string itself */
		m[n] = struct{}{}
		/* With hyphens */
		m[strings.Replace(n, ".", "-", -1)] = struct{}{}
		/* With dots */
		m[strings.Replace(n, "-", ".", -1)] = struct{}{}
		/* Switching them */
		m[strings.Map(func(r rune) rune {
			switch r {
			case '.':
				return '-'
			case '-':
				return '.'
			default:
				return r
			}
		}, n)] = struct{}{}
	}

	/* Compress runs of .. */
	for k := range m {
		if !strings.Contains(k, "..") {
			continue
		}
		delete(m, k)
		for strings.Contains(k, "..") {
			strings.Replace(k, "..", ".", -1)
		}
		m[k] = struct{}{}
	}

	/* Send them out */
	for k := range m {
		c <- k
	}
}

/* getTags returns a slice of tags to use.  If fn is "no", it returns an empty
slice.  If fn is the empty string, it returns tags from TAGLIST.  Otherwise
fn is treated as a filename and tags are read from the file, one per line.
Blank lines and comments are skipped. */
func getTags(fn string) ([]string, error) {
	/* No means no tags */
	if "no" == fn {
		return nil, nil
	}
	/* Empty means use the built-in list */
	if "" == fn {
		return TAGLIST, nil
	}

	/* Try reading tags from the file */
	/* Open file */
	f, err := os.Open(fn)
	if nil != err {
		return nil, err
	}
	/* Read each line, appending it to o if it's a tag */
	s := bufio.NewScanner(f)
	var o []string
	for s.Scan() {
		/* Line from file */
		l := strings.TrimSpace(s.Text())
		/* Skip blank lines and comments */
		if "" == l || strings.HasPrefix(l, "#") {
			continue
		}
		o = append(o, l)
	}
	if err := s.Err(); nil != err {
		return nil, err
	}
	return o, nil
}

// TAGLIST contains the default list of tags to try to prepend and append to
// names
var TAGLIST = []string{
	"admin",
	"administrator",
	"alpha",
	"android",
	"app",
	"artifacts",
	"assets",
	"audit",
	"audit-logs",
	"aws",
	"aws-logs",
	"awslogs",
	"backup",
	"backups",
	"bak",
	"bamboo",
	"beta",
	"betas",
	"billing",
	"blog",
	"bucket",
	"build",
	"builds",
	"cache",
	"cdn",
	"club",
	"cluster",
	"common",
	"consultants",
	"contact",
	"corp",
	"corporate",
	"data",
	"dev",
	"developer",
	"developers",
	"development",
	"devops",
	"directory",
	"discount",
	"dl",
	"dns",
	"docker",
	"download",
	"downloads",
	"dynamo",
	"dynamodb",
	"ec2",
	"ecs",
	"elastic",
	"elb",
	"elk",
	"emails",
	"es",
	"events",
	"export",
	"files",
	"fileshare",
	"gcp",
	"git",
	"github",
	"gitlab",
	"graphite",
	"graphql",
	"help",
	"hub",
	"iam",
	"images",
	"img",
	"infra",
	"internal",
	"internal-tools",
	"ios",
	"jira",
	"js",
	"kubernetes",
	"landing",
	"ldap",
	"loadbalancer",
	"logs",
	"logstash",
	"mail",
	"main",
	"manuals",
	"mattermost",
	"media",
	"mercurial",
	"mobile",
	"mysql",
	"ops",
	"oracle",
	"packages",
	"photos",
	"pics",
	"pictures",
	"postgres",
	"presentations",
	"preview",
	"private",
	"pro",
	"prod",
	"production",
	"products",
	"project",
	"projects",
	"psql",
	"public",
	"rds",
	"repo",
	"reports",
	"resources",
	"s3",
	"screenshots",
	"scripts",
	"sec",
	"security",
	"services",
	"share",
	"shop",
	"sitemaps",
	"slack",
	"snapshots",
	"source",
	"splunk",
	"src",
	"stage",
	"staging",
	"static",
	"stats",
	"storage",
	"store",
	"subversion",
	"support",
	"svn",
	"syslog",
	"teamcity",
	"temp",
	"templates",
	"terraform",
	"test",
	"tmp",
	"traffic",
	"training",
	"travis",
	"troposphere",
	"uploads",
	"userpictures",
	"users",
	"ux",
	"videos",
	"web",
	"website",
	"wp",
	"www",
}
