import boto.provider
from boto.compat import urllib


qsa_of_interest = ['acl', 'cors', 'defaultObjectAcl', 'location', 'logging',
                   'partNumber', 'policy', 'requestPayment', 'torrent',
                   'versioning', 'versionId', 'versions', 'website',
                   'uploads', 'uploadId', 'response-content-type',
                   'response-content-language', 'response-expires',
                   'response-cache-control', 'response-content-disposition',
                   'response-content-encoding', 'delete', 'lifecycle',
                   'tagging', 'restore',
                   # storageClass is a QSA for buckets in Google Cloud Storage.
                   # (StorageClass is associated to individual keys in S3, but
                   # having it listed here should cause no problems because
                   # GET bucket?storageClass is not part of the S3 API.)
                   'storageClass',
                   # websiteConfig is a QSA for buckets in Google Cloud
                   # Storage.
                   'websiteConfig',
                   # compose is a QSA for objects in Google Cloud Storage.
                   'compose']


def unquote_v(nv):
    if len(nv) == 1:
        return nv
    else:
        return (nv[0], urllib.parse.unquote(nv[1]))


def canonical_string(method, path, headers, expires=None,
                     provider=None):
    """
    Generates the aws canonical string for the given parameters
    """
    if not provider:
        provider = boto.provider.get_default()
    interesting_headers = {}
    for key in headers:
        lk = key.lower()
        if headers[key] is not None and \
                (lk in ['content-md5', 'content-type', 'date'] or
                 lk.startswith(provider.header_prefix)):
            interesting_headers[lk] = str(headers[key]).strip()

    # these keys get empty strings if they don't exist
    if 'content-type' not in interesting_headers:
        interesting_headers['content-type'] = ''
    if 'content-md5' not in interesting_headers:
        interesting_headers['content-md5'] = ''

    # just in case someone used this.  it's not necessary in this lib.
    if provider.date_header in interesting_headers:
        interesting_headers['date'] = ''

    # if you're using expires for query string auth, then it trumps date
    # (and provider.date_header)
    if expires:
        interesting_headers['date'] = str(expires)

    sorted_header_keys = sorted(interesting_headers.keys())

    buf = "%s\n" % method
    for key in sorted_header_keys:
        val = interesting_headers[key]
        if key.startswith(provider.header_prefix):
            buf += "%s:%s\n" % (key, val)
        else:
            buf += "%s\n" % val

    # don't include anything after the first ? in the resource...
    # unless it is one of the QSA of interest, defined above
    t = path.split('?')
    buf += t[0]

    if len(t) > 1:
        qsa = t[1].split('&')
        qsa = [a.split('=', 1) for a in qsa]
        qsa = [unquote_v(a) for a in qsa if a[0] in qsa_of_interest]
        if len(qsa) > 0:
            qsa.sort(key=lambda x: x[0])
            qsa = ['='.join(a) for a in qsa]
            buf += '?'
            buf += '&'.join(qsa)

    return buf


def merge_meta(headers, metadata, provider=None):
    if not provider:
        provider = boto.provider.get_default()
    metadata_prefix = provider.metadata_prefix
    final_headers = headers.copy()
    for k in metadata.keys():
        if k.lower() in boto.s3.key.Key.base_user_settable_fields:
            final_headers[k] = metadata[k]
        else:
            final_headers[metadata_prefix + k] = metadata[k]

    return final_headers


def get_aws_metadata(headers, provider=None):
    if not provider:
        provider = boto.provider.get_default()
    metadata_prefix = provider.metadata_prefix
    metadata = {}
    for hkey in headers.keys():
        if hkey.lower().startswith(metadata_prefix):
            val = urllib.parse.unquote(headers[hkey])
            if isinstance(val, bytes):
                try:
                    val = val.decode('utf-8')
                except UnicodeDecodeError:
                    # Just leave the value as-is
                    pass
            metadata[hkey[len(metadata_prefix):]] = val
            del headers[hkey]
    return metadata