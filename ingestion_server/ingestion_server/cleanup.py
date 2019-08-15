import logging as log
import requests as re
import json
import ast
import random
from ingestion_server.indexer import database_connect, DB_BUFFER_SIZE
from urllib.parse import urlparse
from tld import get_tld
from tld.utils import update_tld_names
from tld.exceptions import TldBadUrl
update_tld_names()
"""
Functions for processing data when it is imported into the CC Catalog. This 
includes cleaning up malformed URLs and filtering out undesirable tags.
"""

# Number of records to buffer in memory at once
CLEANUP_BUFFER_SIZE = DB_BUFFER_SIZE

# Filter out tags that exactly match these terms. All terms should be lowercase.
TAG_BLACKLIST = {
    'no person',
    'squareformat',
    'uploaded:by=flickrmobile',
    'uploaded:by=instagram',
    'flickriosapp:filter=flamingo',
    'cc0',
    'by',
    'by-nc',
    'by-nd',
    'by-sa',
    'by-nc-nd',
    'by-nc-sa',
    'pdm'
}

# Filter out tags that contain the following terms. All entrees should be
# lowercase.
TAG_CONTAINS_BLACKLIST = {
    'flickriosapp',
    'uploaded',
    ':',
    '='
}

# Filter out low-confidence tags, which indicate that the machine-generated tag
# may be inaccurate.
TAG_MIN_CONFIDENCE = 0.90


def _tag_blacklisted(tag):
    """ Tag is banned or contains a banned substring. """
    if tag in TAG_BLACKLIST:
        return True
    for blacklisted_substring in TAG_CONTAINS_BLACKLIST:
        if blacklisted_substring in tag:
            return True
    return False


def _jsonify(_json):
    return str(json.loads(_json))


class CleanupFunctions:
    """
    A cleanup function takes one parameter and returns the "cleaned" version if
    an update is required, otherwise None.

    Cleanup functions are dispatched in the _cleanup_config dictionary.
    """
    @staticmethod
    def cleanup_url(url, tls_support):
        """
        Add protocols to the URI if they are missing, else return None.
        """
        parsed = urlparse(url)
        if parsed.scheme == '':
            try:
                _tld = get_tld('https://' + url, as_object=True)
                _tld = _tld.subdomain + '.' + _tld.domain + '.' + _tld.tld
                _tld = str(_tld)
            except TldBadUrl:
                _tld = 'unknown'
                log.info('Failed to parse url {}'.format(url))
            try:
                tls_supported = tls_support[_tld]
            except KeyError:
                tls_supported = TlsTest.test_tls_supported(url)
                tls_support[_tld] = tls_supported
                log.info('Tested domain {}'.format(_tld))

            if tls_supported:
                return "'https://{}'".format(url)
            else:
                return "'http://{}'".format(url)
        else:
            return url

    @staticmethod
    def cleanup_tags(tags):
        """
        Delete tags because they have low accuracy or because they are in the
        blacklist. If no change is made, return None.
        :return: A SQL fragment if an update is required or None
        """
        update_required = False
        tag_output = []
        if not tags:
            return tags

        try:
            tags = ast.literal_eval(tags)
        except SyntaxError:
            log.warning('Skipped invalid json')
            return '\\N'
        for tag in tags:
            below_threshold = False
            if 'accuracy' in tag and tag['accuracy'] < TAG_MIN_CONFIDENCE:
                below_threshold = True
            lower_tag = tag['name'].lower()
            should_filter = _tag_blacklisted(lower_tag) or below_threshold
            if not should_filter:
                tag_output.append(tag)
                update_required = True

        if update_required:
            fragment = json.dumps(tag_output)
            return fragment
        else:
            return json.dumps(tag_output)


# Define which tables, providers, and fields require cleanup. Map the field
# to a cleanup function that returns either a cleaned version of the field
# or 'None' to signal that no update is required.
_cleanup_config = {
    'tables': {
        'image': {
            # Applies to all providers.
            'fields': {
                'tags': CleanupFunctions.cleanup_tags,
                'url': CleanupFunctions.cleanup_url,
                'creator_url': CleanupFunctions.cleanup_url,
                'foreign_landing_url': CleanupFunctions.cleanup_url,
                'thumbnail': CleanupFunctions.cleanup_url
            }
        }
    }
}


class TlsTest:
    """
    URLs crawled from upstream are often lacking protocol information, or
    use HTTP when HTTPS is available. We have to test a small sample of the
    URLs to determine what protocol should be appended to each URL in the
    event that it is missing or incorrect.
    """
    @classmethod
    def test_tls_supported(cls, url):
        # No protocol provided
        if 'https://' not in url and 'http://' not in url:
            fixed_url = 'http://' + url
            return cls.test_tls_supported(fixed_url)
        # HTTP provided, but we want to check if HTTPS is supported as well.
        elif 'http://' in url:
            https = url.replace('http://', 'https://')
            try:
                res = re.get(https, timeout=2)
                log.info('{}:{}'.format(https, res.status_code))
                return 200 <= res.status_code < 400
            except re.RequestException:
                return False
        # If HTTPS is in the URL already, we're going to trust that HTTPS is
        # supported.
        return True


def _parse_copy_directive_fields(directive):
    """
    Parse the COPY(field1, field2, . . . field n) command.
    """
    fields_start = directive.find('(') + 1
    fields_end = directive.find(')')
    return directive[fields_start:fields_end].split(', ')


def _write_wrapper(line, table_name, file_handle):
    """
    We want to load the cleaned data to a temporary table. As a result, we have
    to rename the table in any SQL statements where it appears.

    Additionally, in Postgres, indices have global names. To prevent collisions,
    we have to strip the name and let Postgres come up with one itself.

    :param line: A line containing a sql statement.
    :param table_name: The ORIGINAL name of the table.
    :param file_handle: The file to write the updated SQL statement to.
    """
    # Rename to temporary table.
    updated = line.replace(
        'public.{}'.format(table_name),
        'public.temp_import_{}'.format(table_name)
    )
    # Remove index and constraint names.
    parsed = updated.split(' ')
    if 'CREATE INDEX' in updated:
        del parsed[2]
    elif 'ADD CONSTRAINT' in updated:
        location = parsed.index('CONSTRAINT')
        parsed[location + 1] = '"' + ''.join(
            random.choice('0123456789ABCDEF') for _ in range(8)
        ) + '"'
    elif 'CREATE UNIQUE INDEX' in updated:
        del parsed[3]
    updated = ' '.join(parsed)

    file_handle.write(updated)


def clean_dump(dump_filename, table_name):
    """
    Given a psql .sql dump file, parse it and clean up the raw data according
    to our custom rules.

    :param dump_filename:
    :param table_name:
    :return:
    """
    cleaned_file = dump_filename + '_clean'
    cleaning_rules = _cleanup_config['tables'][table_name]['fields']
    tls_cache = {}
    progress = 0
    with open(dump_filename, 'r') as f, open(cleaned_file, 'w+') as c:
        # Seek to the data section of the table dump.
        while True:
            line = f.readline()
            _write_wrapper(line, table_name, c)
            if not line:
                log.error('Failed to parse SQL dump.')
                return False
            if 'COPY public.{}'.format(table_name) in line:
                header = _parse_copy_directive_fields(line)
                break
        # Clean the data line by line. Columns are delimited by tabs.
        while True:
            line = f.readline().rstrip()
            if line == '\.':
                # We've reached the end of the data section.
                c.write('\.\n')
                break
            row = line.split('\t')
            cleaned_row = []
            for idx, value in enumerate(row):
                if value == '\\N':
                    value = None
                field_name = header[idx]
                if value and field_name in cleaning_rules:
                    cleaning_func = cleaning_rules[field_name]
                    if cleaning_func == CleanupFunctions.cleanup_url:
                        clean = cleaning_func(
                            url=value, tls_support=tls_cache
                        )
                    else:
                        clean = cleaning_func(value)
                    cleaned_row.append(clean)
                elif not value:
                    cleaned_row.append('\\N')
                else:
                    cleaned_row.append(value)
            cleaned_row_str = '\t'.join(cleaned_row)
            c.write(cleaned_row_str + '\n')
            progress += 1
            if progress % 1000000 == 0:
                log.info('Cleaned {} rows so far'.format(progress))
