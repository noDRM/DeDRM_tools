# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:ai
from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

__license__   = 'GPL v3'
__docformat__ = 'restructuredtext en'

'''
Title matching between Kobo books and the calibre library.

Kobo and calibre maintain a book's title independently, so a plain exact
string compare misses a large fraction of real duplicates:

  * smart vs straight quotes/apostrophes ("All the King's Men")
  * a subtitle present on one side only  ("Born a Crime: Stories ...")
  * a trailing parenthetical / edition tag ("... (Pulitzer Prize Winner)",
    "... 10th Anniversary")
  * "&" vs "and"

`normalize_title` canonicalizes a title so the two sides can be compared
reliably; it MUST be applied identically to both sides.  `LibraryMatcher`
wraps the calibre side and, when the normalized forms don't match exactly,
falls back to a bounded Levenshtein (edit-distance) similarity check to catch
typos and minor variations.

This module deliberately has no calibre / Qt imports so it can be unit tested
on its own (see tests/test_title_match.py).
'''

import re
import unicodedata

# Punctuation that differs between Kobo and calibre but should be treated as
# equivalent.  Folded before the (lossy) generic punctuation pass below so that
# colon/paren detection still works on already-folded text.
_QUOTE_FOLDS = {
    '‘': "'", '’': "'", '‚': "'", '‛': "'",
    '´': "'", '`': "'",
    '“': '"', '”': '"', '„': '"', '‟': '"',
    '–': '-', '—': '-', '‒': '-', '―': '-', '−': '-',
}

# A trailing parenthetical/bracketed group, e.g. " (Pulitzer Prize Winner)".
_TRAILING_BRACKET_RE = re.compile(r'\s*[\(\[\{][^\(\)\[\]\{\}]*[\)\]\}]\s*$')

# A trailing edition descriptor, e.g. " 10th Anniversary", " Deluxe Edition".
# "anniversary" may stand alone (rarely a real title word); the others must be
# followed by "edition" to avoid stripping legitimate title words.
_EDITION_SUFFIX_RE = re.compile(
    r'\s+(?:'
    r'(?:\d+\s*(?:st|nd|rd|th)\s+)?anniversary(?:\s+edition)?'
    r'|(?:deluxe|revised|expanded|updated|illustrated|annotated|special'
    r'|definitive|collector\'?s?|unabridged|abridged|reprint)\s+edition'
    r')\s*$'
)

_NON_ALNUM_RE = re.compile(r'[^\w\s]', re.UNICODE)
_WHITESPACE_RE = re.compile(r'\s+')

# An English article at the front ("The Hobbit") or moved to the end in
# calibre's sort form ("Hobbit, The", which normalizes to a trailing " the").
_LEADING_ARTICLE_RE = re.compile(r'^(?:the|a|an)\s+')
_TRAILING_ARTICLE_RE = re.compile(r'\s+(?:the|a|an)$')

# Fuzzy-match tuning.  Kept as module constants so they're trivial to adjust
# from observed behaviour (the dialog logs every fuzzy match it makes).
FUZZY_THRESHOLD = 0.87   # minimum similarity (1.0 == identical) to accept
FUZZY_MIN_LEN = 6        # don't fuzzy-match titles shorter than this


def normalize_title(title, strip_subtitle=True):
    '''
    Canonicalize a book title for comparison.  Returns a lowercased, punctuation
    -folded string with parenthetical / edition noise removed.  When
    `strip_subtitle` is true (default) the part after the first colon is also
    dropped.  Prefer `title_keys` for matching, which considers both forms.
    '''
    if not title:
        return ''
    try:
        s = unicodedata.normalize('NFKC', title)
    except TypeError:
        # py2 bytes safety net; modern calibre passes unicode.
        s = unicodedata.normalize('NFKC', title.decode('utf-8', 'replace'))
    for src, dst in _QUOTE_FOLDS.items():
        if src in s:
            s = s.replace(src, dst)
    s = s.lower()
    s = s.replace('&', ' and ')
    if strip_subtitle:
        # Drop subtitle after the first colon ("Born a Crime: Stories ..." -> ...).
        s = s.split(':', 1)[0]
    # Strip trailing parenthetical/bracketed groups (possibly nested/repeated).
    prev = None
    while prev != s:
        prev = s
        s = _TRAILING_BRACKET_RE.sub('', s)
    # Strip a trailing edition descriptor.
    s = _EDITION_SUFFIX_RE.sub('', s)
    # Fold any remaining punctuation (apostrophes, hyphens, %, ...) to spaces.
    s = _NON_ALNUM_RE.sub(' ', s)
    s = _WHITESPACE_RE.sub(' ', s).strip()
    return s


def title_keys(title):
    '''
    The set of normalized forms a title can match on: the subtitle-stripped form
    AND the full form (colon kept as a separator).  Comparing the sets on both
    sides means "Foo: Bar" matches a bare "Foo" *and* a colon-less "Foo Bar".
    '''
    keys = set()
    stripped = normalize_title(title, strip_subtitle=True)
    if stripped:
        keys.add(stripped)
    full = normalize_title(title, strip_subtitle=False)
    if full:
        keys.add(full)
    return keys


def _article_key(normalized):
    '''
    Reduce an already-normalized title to an article-insensitive key by removing
    an article at the front ("the hobbit") or the end (calibre's "hobbit, the",
    which normalizes to a trailing " the").
    '''
    s = _LEADING_ARTICLE_RE.sub('', normalized)
    s = _TRAILING_ARTICLE_RE.sub('', s)
    return s.strip()


def normalize_author(author):
    '''
    Canonicalize an author for comparison.  Lowercases, drops punctuation, and
    sorts the name tokens so display order / "Last, First" don't matter
    ("Robert Penn Warren" == "Warren, Robert Penn").  Returns '' if unknown.
    '''
    if not author:
        return ''
    try:
        s = unicodedata.normalize('NFKC', author)
    except TypeError:
        s = unicodedata.normalize('NFKC', author.decode('utf-8', 'replace'))
    s = s.lower()
    s = _NON_ALNUM_RE.sub(' ', s)
    return ' '.join(sorted(s.split()))


def _strong_tokens(na):
    '''
    The distinctive tokens of a normalized author string: alphabetic name parts
    of length >= 3.  Drops single initials ("j") and purely numeric junk (an
    ISBN or year that crept into the author field, as calibre sometimes stores).
    '''
    return frozenset(t for t in na.split() if len(t) >= 3 and not t.isdigit())


def _bounded_levenshtein(a, b, max_dist):
    '''
    Levenshtein edit distance between `a` and `b`, but returns `max_dist + 1`
    as soon as the distance is guaranteed to exceed `max_dist`.  The early-out
    keeps the per-comparison cost low when scanning a large library.
    '''
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1
    if la == 0:
        return lb
    if lb == 0:
        return la
    if la > lb:                      # keep the inner row short
        a, b = b, a
        la, lb = lb, la
    previous = list(range(la + 1))
    for j in range(1, lb + 1):
        current = [j] + [0] * la
        bj = b[j - 1]
        row_min = current[0]
        for i in range(1, la + 1):
            cost = 0 if a[i - 1] == bj else 1
            current[i] = min(previous[i] + 1,
                             current[i - 1] + 1,
                             previous[i - 1] + cost)
            if current[i] < row_min:
                row_min = current[i]
        if row_min > max_dist:
            return max_dist + 1
        previous = current
    return previous[la]


class _AuthorGroup(object):
    '''Title keys for all library books by one (normalized) author.'''
    __slots__ = ('titles', 'article')

    def __init__(self):
        self.titles = set()    # every title key by this author
        self.article = {}      # article key -> title key

    def add(self, keys):
        self.titles.update(keys)
        for k in keys:
            self.article[_article_key(k)] = k


class LibraryMatcher(object):
    '''
    Decides whether a (Kobo) book is already present in the calibre library.

    A book is the same when the AUTHOR(S) agree *and* the title harmonizes.
    Author agreement is checked first: authors are normalized to a set of name
    tokens, tolerant of order, "Last, First", separators, and one side listing
    extra authors (subset/superset).  Only within a matching author's books are
    titles compared -- exact normalized form, then leading/trailing article,
    then bounded fuzzy.  A book with no usable author falls back to an exact
    full-title match only (no fuzzy).  Treat as immutable after construction.
    '''

    def __init__(self, entries, fuzzy=True,
                 threshold=FUZZY_THRESHOLD, min_len=FUZZY_MIN_LEN):
        '''
        :param entries: iterable of calibre books; each item is either a title
            string or a ``(title, author)`` pair.
        '''
        self._fuzzy = fuzzy
        self._threshold = threshold
        self._min_len = min_len
        self._all_titles = set()     # every title key (for the no-author fallback)
        self._groups = {}            # normalized author -> _AuthorGroup
        self._token_to_authors = {}  # strong author token -> set of normalized authors
        for entry in entries:
            if isinstance(entry, (tuple, list)):
                title = entry[0]
                author = entry[1] if len(entry) > 1 else ''
            else:
                title, author = entry, ''
            keys = title_keys(title)
            if not keys:
                continue
            self._all_titles.update(keys)
            na = normalize_author(author)
            if not na:
                continue
            group = self._groups.get(na)
            if group is None:
                group = self._groups[na] = _AuthorGroup()
                for tok in _strong_tokens(na):
                    self._token_to_authors.setdefault(tok, set()).add(na)
            group.add(keys)

    def __len__(self):
        return len(self._all_titles)

    def title_exists(self, title):
        '''
        True if the title alone (ignoring author) matches some library book.
        For diagnostics: title_exists() True while match() is None means the
        title is present but under a different author.
        '''
        return bool(title_keys(title) & self._all_titles)

    def contains(self, title, author=None):
        '''True if `title` by `author` matches a book already in the library.'''
        return self.match(title, author) is not None

    def match(self, title, author=None):
        '''
        Return the normalized calibre title that `title` (by `author`) matches,
        or None.  Author is checked first; within a matching author, the title
        is harmonized (exact form -> leading/trailing article -> bounded fuzzy).
        (Returning the match -- not just a bool -- lets callers log *why*
        something was considered a duplicate.)
        '''
        keys = title_keys(title)
        if not keys:
            return None
        na = normalize_author(author)
        if not na:
            # Author unknown: only trust an exact title match, nothing looser.
            for k in keys:
                if k in self._all_titles:
                    return k
            return None
        for group in self._candidate_groups(na):
            # exact title within this author
            for k in keys:
                if k in group.titles:
                    return k
            # same author, article-insensitive ("The X" / "X" / "X, The")
            for k in keys:
                hit = group.article.get(_article_key(k))
                if hit is not None:
                    return hit
            # same author, bounded fuzzy title
            hit = self._fuzzy_title(keys, group.titles)
            if hit is not None:
                return hit
        return None

    def _candidate_groups(self, na):
        '''
        Yield author groups that plausibly denote the same author as `na`: the
        exact author first, then any author sharing a strong name token (see
        `_strong_tokens`).  This tolerates honorifics / ordination names ("Bhante"
        vs "Henepola Gunaratana"), abbreviated middles ("Oren J." vs "Oren Jay"),
        one side listing extra authors, and junk tokens like an ISBN calibre
        stored as a second author.  The caller's title check keeps it honest.
        '''
        seen = set()
        exact = self._groups.get(na)
        if exact is not None:
            seen.add(na)
            yield exact
        candidates = set()
        for tok in _strong_tokens(na):
            candidates |= self._token_to_authors.get(tok, set())
        for other_na in candidates:
            if other_na in seen:
                continue
            seen.add(other_na)
            yield self._groups[other_na]

    def _fuzzy_title(self, keys, titles):
        if not self._fuzzy:
            return None
        n = max(keys, key=len)
        if len(n) < self._min_len:
            return None
        ln = len(n)
        threshold = self._threshold
        for cand in titles:
            lc = len(cand)
            longest = ln if ln > lc else lc
            if longest == 0:
                continue
            # Cheap upper bound on similarity from the length gap alone.
            if (1.0 - (abs(ln - lc) / float(longest))) < threshold:
                continue
            max_dist = int((1.0 - threshold) * longest)
            if _bounded_levenshtein(n, cand, max_dist) <= max_dist:
                return cand
        return None