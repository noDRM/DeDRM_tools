# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:ai
'''
Unit tests for title_match.normalize_title / LibraryMatcher.

These use the real Kobo titles surfaced by the diagnostic build against
Erez's library (the ones that exact-matching missed), so the tests document
the actual failure modes we're fixing.

Run from the repo root:  pytest -v   (or: python3 -m pytest -v)
'''
from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

import os
import sys

# title_match lives inside the Obok_plugin package dir; add it to the path so we
# can import the module without importing the package (whose __init__ needs calibre).
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Obok_plugin'))

from title_match import normalize_title, normalize_author, LibraryMatcher  # noqa: E402

CURLY = '’'  # right single quotation mark (Kobo's apostrophe)


def n(t):
    return normalize_title(t)


# --- normalize_title: the three observed drift buckets -----------------------

def test_smart_apostrophe_folds_to_straight():
    # Kobo stores a curly apostrophe; calibre a straight one.
    assert n('All The King' + CURLY + 's Men') == n("All the King's Men")
    assert n('Assassin' + CURLY + 's Apprentice') == n("Assassin's Apprentice")
    assert n('Cat' + CURLY + 's Cradle') == n("Cat's Cradle")


def test_subtitle_after_colon_is_dropped():
    assert n('Born a Crime') == n('Born a Crime: Stories from a South African Childhood')
    assert n('Be Useful') == n('Be Useful: Seven Tools for Life')
    assert n('Co-Intelligence') == n('Co-Intelligence: Living and Working with AI')


def test_trailing_parenthetical_is_dropped():
    assert n('American Prometheus (Pulitzer Prize Winner)') == \
        n('American Prometheus: The Triumph and Tragedy of J. Robert Oppenheimer')


def test_parenthetical_and_subtitle_combined():
    assert n('Behold the Dreamers') == n("Behold the Dreamers (Oprah's Book Club): A Novel")


def test_trailing_edition_descriptor_is_dropped():
    assert n('10% Happier 10th Anniversary') == n('10% Happier')
    assert n('Dune Deluxe Edition') == n('Dune')


def test_ampersand_equals_and():
    assert n('Crime & Punishment') == n('Crime and Punishment')


def test_distinct_titles_do_not_collide():
    assert n('The Hobbit') != n('The Silmarillion')
    assert n('Dune') != n('Dune Messiah')
    assert n('Be Useful') != n('Be Quiet')


# --- LibraryMatcher: exact-after-normalization -------------------------------

LIBRARY = [
    "All the King's Men",
    'Born a Crime: Stories from a South African Childhood',
    'Be Useful: Seven Tools for Life',
    '10% Happier',
    'American Prometheus: The Triumph and Tragedy of J. Robert Oppenheimer',
    'The Hobbit',
    'The Lord of the Rings',
]


def test_matcher_finds_normalized_duplicates():
    m = LibraryMatcher(LIBRARY)
    assert m.contains('All The King' + CURLY + 's Men')
    assert m.contains('Born a Crime')
    assert m.contains('Be Useful')
    assert m.contains('10% Happier 10th Anniversary')
    assert m.contains('American Prometheus (Pulitzer Prize Winner)')


def test_matcher_rejects_book_not_in_library():
    m = LibraryMatcher(LIBRARY)
    assert not m.contains('A Wizard of Earthsea')
    assert not m.contains('Assassin' + CURLY + 's Apprentice')


# --- LibraryMatcher: bounded fuzzy fallback ----------------------------------

def test_fuzzy_catches_minor_variation():
    # Fuzzy now runs only within a matching author.
    m = LibraryMatcher([('The Lord of the Rings', 'J.R.R. Tolkien')])
    assert m.contains('The Lord of the Ring', 'J.R.R. Tolkien')   # singular typo
    assert m.contains('The Lord of teh Rings', 'J.R.R. Tolkien')  # transposition


def test_fuzzy_disabled_for_short_titles():
    m = LibraryMatcher([('Dune', 'Frank Herbert')])
    assert not m.contains('June', 'Frank Herbert')  # 1 edit away, too short to fuzzy


def test_fuzzy_threshold_rejects_different_book():
    m = LibraryMatcher([('The Hobbit', 'J.R.R. Tolkien')])
    assert not m.contains('The Rabbit', 'J.R.R. Tolkien')  # similar but different book


def test_fuzzy_requires_matching_author():
    m = LibraryMatcher([('The Lord of the Rings', 'J.R.R. Tolkien')])
    assert not m.contains('The Lord of the Ring', 'Somebody Else')  # author gate


# --- author-first behaviour --------------------------------------------------

def test_no_author_falls_back_to_exact_title_only():
    m = LibraryMatcher([('The Lord of the Rings', 'J.R.R. Tolkien')])
    assert m.contains('The Lord of the Rings')      # exact title, no author -> ok
    assert not m.contains('The Lord of the Ring')   # looser matching needs an author


def test_author_subset_still_matches():
    # Kobo lists only one of the two co-authors; calibre lists both.
    m = LibraryMatcher([('Good Omens', 'Terry Pratchett & Neil Gaiman')])
    assert m.contains('Good Omens', 'Neil Gaiman')


def test_same_title_different_author_is_not_a_match():
    # Title collision across authors must NOT match (the precision win).
    m = LibraryMatcher([('Twilight', 'Stephenie Meyer')])
    assert not m.contains('Twilight', 'William Gay')


# --- real-world author drift (from Erez's library) ---------------------------

def test_isbn_stored_as_second_author_is_ignored():
    # calibre stored an ISBN as a 2nd "author"; Kobo adds the illustrator.
    m = LibraryMatcher([('Chloe and Cracker', 'Kelly McKain & 9781847153395')])
    assert m.contains('Chloe and Cracker', 'Kelly McKain, Mandy Stanley')


def test_honorific_vs_ordination_name_shares_surname():
    m = LibraryMatcher([('Mindfulness in Plain English', 'Henepola Gunaratana')])
    assert m.contains('Mindfulness in Plain English', 'Bhante Gunaratana')


def test_abbreviated_middle_name_and_subtitle():
    m = LibraryMatcher([('Say What You Mean: A Mindful Approach to Nonviolent '
                         'Communication', 'Oren J. Sofer')])
    assert m.contains('Say What You Mean', 'Oren Jay Sofer')


def test_shared_first_name_alone_does_not_match_different_titles():
    # Sharing only a first name is allowed as an author candidate, but the title
    # gate still prevents merging genuinely different books.
    m = LibraryMatcher([('The Firm', 'John Grisham')])
    assert not m.contains('A Perfect Spy', 'John le Carre')


def test_match_returns_the_matched_title():
    m = LibraryMatcher(['Born a Crime: Stories from a South African Childhood'])
    assert m.match('Born a Crime') == normalize_title('Born a Crime')
    assert m.match('Something Else Entirely') is None


# --- normalize_author --------------------------------------------------------

def test_author_order_and_format_are_ignored():
    # Flipped order and "Last, First" both reduce to the same key.
    assert normalize_author('Grisham, John') == normalize_author('John Grisham')
    assert normalize_author('Robert Penn Warren') == normalize_author('Warren, Robert Penn')


def test_distinct_authors_differ():
    assert normalize_author('John Grisham') != normalize_author('Stephen King')


# --- LibraryMatcher: same-author, article-insensitive match ------------------

def test_leading_article_match_when_author_agrees():
    m = LibraryMatcher([('The Hobbit', 'J.R.R. Tolkien')])
    assert m.contains('Hobbit', 'J.R.R. Tolkien')        # Kobo dropped "The"
    assert m.contains('Hobbit', 'Tolkien, J.R.R.')       # + flipped author


def test_trailing_article_sort_form_matches():
    # calibre stores the sort form "..., A"; Kobo has the natural "A ...".
    m = LibraryMatcher([('Guide for the Good Life, A', 'William Irvine')])
    assert m.contains('A Guide for the Good Life', 'William Irvine')
    # ...and the reverse direction.
    m2 = LibraryMatcher([('A Guide for the Good Life', 'Irvine, William')])
    assert m2.contains('Guide for the Good Life, A', 'William Irvine')


def test_article_match_requires_matching_author():
    m = LibraryMatcher([('The Hobbit', 'J.R.R. Tolkien')])
    assert not m.contains('Hobbit', 'Someone Else')   # author gate blocks it
    assert not m.contains('Hobbit')                   # no author -> no gate, no match


def test_article_match_does_not_merge_different_books_same_author():
    m = LibraryMatcher([('The Stand', 'Stephen King')])
    assert not m.contains('It', 'Stephen King')       # same author, different book


# --- multi-author + colon-vs-no-colon (the New Yorker case) ------------------

def test_multi_author_order_and_separator_ignored():
    assert normalize_author('David Remnick & Bob Mankoff') == \
        normalize_author('Bob Mankoff, David Remnick')


def test_colon_in_one_title_only_still_matches():
    # Kobo writes the full title with a colon; calibre without one.
    m = LibraryMatcher([('The New Yorker Encyclopedia of Cartoons',
                         'Bob Mankoff, David Remnick')])
    assert m.contains('The New Yorker: Encyclopedia of Cartoons',
                      'David Remnick & Bob Mankoff')
    # ...and the reverse (colon on the calibre side).
    m2 = LibraryMatcher([('The New Yorker: Encyclopedia of Cartoons',
                          'Bob Mankoff & David Remnick')])
    assert m2.contains('The New Yorker Encyclopedia of Cartoons',
                       'David Remnick, Bob Mankoff')


def test_colon_subtitle_only_on_one_side_still_matches_bare_title():
    # The original "Born a Crime" behaviour must still hold (stripped-form match).
    m = LibraryMatcher(['Born a Crime: Stories from a South African Childhood'])
    assert m.contains('Born a Crime')
