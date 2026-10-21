#!/usr/bin/env python3
# Decision-table check for the nginx maps (block vs pass) without starting nginx.
# Models $request_uri vs $uri: on an internal redirect to the error page, $request_uri stays
# the original URI while $uri becomes /error/NNN.html. The $pp_errpage map keys on $uri.
import re, sys
mp_re = re.compile(r'^(POST|PUT|PATCH):\s*multipart/form-data([;,\s]|$)', re.I)
upload_re = re.compile(r'^/upload(/|\?|$)|^/api/upload(/|\?|$)|^/wp-admin/async-upload\.php(/|\?|$)', re.I)
errpage_re = re.compile(r'^/error/[0-9]{3}\.html$')
def blocked(method, ct, request_uri, uri=None):
    uri = request_uri if uri is None else uri
    mp = 1 if mp_re.search(f"{method}:{ct}") else 0
    up = 1 if upload_re.search(request_uri) else 0
    ep = 1 if errpage_re.search(uri) else 0
    return f"{mp}{up}{ep}" == "100"
MP = "multipart/form-data; boundary=ab"
cases = [
    (not blocked("GET",  "", "/"),                               "GET / non bloccato"),
    (not blocked("POST", "application/x-www-form-urlencoded","/"),"POST urlencoded passa"),
    (    blocked("POST", MP, "/"),                               "POST multipart / bloccato"),
    (not blocked("POST", MP, "/upload"),                         "eccezione /upload esatto"),
    (not blocked("POST", MP, "/upload/img"),                     "eccezione /upload/ subpath"),
    (not blocked("POST", MP, "/upload?x=1"),                     "eccezione /upload?query"),
    (    blocked("POST", MP, "/uploads-x"),                      "/uploads-x NON e' upload -> bloccato"),
    (    blocked("POST", MP, "/uploader"),                       "/uploader NON e' upload -> bloccato"),
    (    blocked("POST", "multipart/form-data,boundary=ab","/"), "variante VIRGOLA bloccata"),
    (    blocked("POST", "MULTIPART/FORM-DATA; boundary=ab","/"),"case-insensitive"),
    (    blocked("PUT",  MP, "/"),                               "PUT multipart bloccato (8.4)"),
    (    blocked("PATCH",MP, "/"),                               "PATCH multipart bloccato (8.4)"),
    (not blocked("POST", "application/json","/"),                "JSON passa"),
    # internal redirect to the error page: request_uri resta "/", uri diventa /error/403.html
    (not blocked("POST", MP, "/", uri="/error/403.html"),        "redirect interno a /error/403.html NON ri-bloccato (niente ciclo 500)"),
]
fail = 0
for ok, desc in cases:
    if not ok: fail += 1
    print(f"[{'OK' if ok else 'FAIL'}] {desc}")
print("\nRESULT:", "PASS" if fail == 0 else f"FAIL ({fail})")
sys.exit(1 if fail else 0)
