# -*- coding: utf-8 -*-
#
import logging
from itertools import chain

from django.db import models
from rest_framework.settings import api_settings

from common.drf.filters import IDSpmFilter, CustomFilter, IDInFilter, IDNotFilter

__all__ = ['ExtraFilterFieldsMixin', 'OrderingFielderFieldsMixin']

logger = logging.getLogger('jumpserver.common')


class ExtraFilterFieldsMixin:
    """
    额外的 api filter
    """
    default_added_filters = [CustomFilter, IDSpmFilter, IDInFilter, IDNotFilter]
    filter_backends = api_settings.DEFAULT_FILTER_BACKENDS
    extra_filter_fields = []
    extra_filter_backends = []

    def set_compatible_fields(self):
        """
        兼容老的 filter_fields
        """
        if not hasattr(self, 'filter_fields') and hasattr(self, 'filterset_fields'):
            self.filter_fields = self.filterset_fields

    def get_filter_backends(self):
        self.set_compatible_fields()
        if self.filter_backends != self.__class__.filter_backends:
            return self.filter_backends
        backends = list(chain(
            self.filter_backends,
            self.default_added_filters,
            self.extra_filter_backends
        ))
        return backends

    def filter_queryset(self, queryset):
        for backend in self.get_filter_backends():
            queryset = backend().filter_queryset(self.request, queryset, self)
        return queryset


class OrderingFielderFieldsMixin:
    """
    额外的 api ordering
    """
    ordering_fields = None
    extra_ordering_fields = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ordering_fields = self._get_ordering_fields()

    def _get_ordering_fields(self):
        if isinstance(self.__class__.ordering_fields, (list, tuple)):
            return self.__class__.ordering_fields

        try:
            valid_fields = self.get_valid_ordering_fields()
        except Exception as e:
            logger.debug('get_valid_ordering_fields error: %s' % e)
            # 这里千万不要这么用，会让 logging 重复，至于为什么，我也不知道
            # logging.debug('get_valid_ordering_fields error: %s' % e)
            valid_fields = []

        fields = list(chain(
            valid_fields,
            self.extra_ordering_fields
        ))
        return fields

    def get_valid_ordering_fields(self):
        if getattr(self, 'model', None):
            model = self.model
        elif getattr(self, 'queryset', None):
            model = self.queryset.model
        else:
            queryset = self.get_queryset()
            model = queryset.model

        if not model:
            return []

        excludes_fields = (
            models.UUIDField, models.Model, models.ForeignKey,
            models.FileField, models.JSONField, models.ManyToManyField,
            models.DurationField,
        )
        valid_fields = []
        for field in model._meta.fields:
            if isinstance(field, excludes_fields):
                continue
            valid_fields.append(field.name)
        return valid_fields
