from rdflib import Graph, Namespace
from rdflib.namespace import DC, DCTERMS
from rdflib.resource import Resource
from django.conf import settings
from django.core.cache import cache, caches

WEB = caches['web']
CC = Namespace('http://creativecommons.org/ns#')

LICENSES = (
    ("BY", "Attribution"),
    ("BY-NC", "Attribution NonCommercial"),
    ("BY-ND", "Attribution NoDerivatives"),
    ("BY-SA", "Attribution ShareAlike"),
    ("BY-NC-ND", "Attribution NonCommercial NoDerivatives"),
    ("BY-NC-SA", "Attribution NonCommercial ShareAlike"),
    ("PDM", "Public Domain Mark"),
    ("CC0", "Public Domain Dedication"),
)

LICENSE_GROUPS = {
    # All open licenses
    "all": {'BY', 'BY-NC', 'BY-ND', 'BY-SA', 'BY-NC-ND', 'BY-NC-SA', 'PDM',
            'CC0'},
    # All CC licenses
    "all-cc": {'BY', 'BY-NC', 'BY-ND', 'BY-SA', 'BY-NC-ND', 'BY-NC-SA', 'CC0'},
    # All licenses allowing commercial use
    "commercial": {'BY', 'BY-SA', 'BY-ND', 'CC0', 'PDM'},
    # All licenses allowing modifications
    "modification": {'BY', 'BY-SA', 'BY-NC', 'BY-NC-SA', 'CC0', 'PDM'},
}

ATTRIBUTION = \
    "{title} {creator}is licensed under CC-{_license} {version}. To view a " \
    "copy of this license, visit {license_url}."


def get_license_url(_license, version, meta_data=None):
    if meta_data and 'license_url' in meta_data:
        return meta_data['license_url']
    if _license.lower() == 'pdm':
        return 'https://creativecommons.org/publicdomain/mark/1.0/'
    else:
        return f'https://creativecommons.org/licenses/{_license}/{version}/'

def parse_and_cache_licenses():
    licenses = []
    license_graph = Graph()
    license_graph.load(settings.LICENSE_RDF_PATH)
    cc_license_resource = Resource(license_graph, CC.License)
    for cc_license in cc_license_resource.subjects():
        license_url = cc_license.identifier
        version = cc_license.value(p=DCTERMS.hasVersion)
        jurisdiction = (cc_license.value(p=CC.jurisdiction)).identifier
        for cc_license_predicate, cc_license_object in cc_license.predicate_objects():
            if cc_license_predicate.qname() == 'dc:title':
                language = cc_license_object.language
                licenses.append({
                    'license_url': license_url,
                    'license_version': version,
                    'jurisdiction': jurisdiction,
                    'language_code': language
                })
    WEB.set(settings.ALL_LICENSES_CACHE_KEY, licenses)
