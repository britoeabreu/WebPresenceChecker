# WebPresenceChecker
Checks whether of a list of provided smart tourism projects' links are still online, by exploring them at three levels: domain, subdomain and page, if applicable. It then produces the following three boolean indicators that are used to build the presence score of each project, a smart-tourism resilience measure:

    DomainFound      the registrable domain (e.g. example.com) responds
    SubdomainFound   the subdomain host (e.g. visit.example.com) responds
                     -- only when the link is hosted on a subdomain
                        (a leading "www." is NOT considered a subdomain)
    PageFound        the full link responds
                     -- only when the link points to a page
                        (a path below the root, or a query string)

and PresenceScore = 0 if not DomainFound, else 1 + (SubdomainFound or PageFound).

Resilience features
-------------------
* Public-suffix aware domain extraction (x.co.uk, x.gov.uk, x.com.tr ...).
* HEAD first, GET fallback when HEAD fails; browser-like User-Agent.
* Scheme fallback (https <-> http) and www/no-www variants.
* Timeouts, bounded retries with exponential back-off for transient errors (timeouts, connection resets, 429/5xx); no retry for definitive answers.
* Invalid TLS certificates are treated as "host alive" (flagged in Notes).
* 401/403 ("blocked") responses are reported separately and, by default, counted as "found" for domain/subdomain checks (the host exists).
* Redirect-to-homepage detection for pages (typical soft 404).
* Optional soft-404 detection (--soft404 text|full) for pages that answer "200" although the content is missing: 
    (a) <title> and first <h1> are searched for "not found" wording in 12 languages (the matched phrase is written to Notes);
    (b) in "full" mode the program also requests a random non-existent address on the same site and compares the answer with the page: same final address, same content or same title and size reveal a site that serves error pages as 200.
* Per-host politeness delay, thread pool, in-memory de-duplication of domain/subdomain/page checks.
* Checkpointing to a JSONL file: an interrupted run (Ctrl-C, crash, network outage) resumes where it stopped. Output is written atomically.
* Initial connectivity test, so that a local network outage is not recorded as a world-wide loss of web presence.
* A sidecar .meta.json file records when and how the check was run.
