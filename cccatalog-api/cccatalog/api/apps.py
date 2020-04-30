from django.apps import AppConfig


class ApiConfig(AppConfig):
    name = 'cccatalog.api'

    def ready(self):
        from cccatalog.api.licenses import parse_and_cache_licenses
        parse_and_cache_licenses()
