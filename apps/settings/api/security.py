from uuid import uuid4

from django.conf import settings
from django.core.cache import cache
from rest_framework.views import Response, APIView

from settings.models import Setting
from users.utils import LoginIpBlockUtil


class BlockIPAPI(APIView):
    rbac_perms = {
        'GET': 'settings.change_security',
    }

    @staticmethod
    def get_ips():
        ips = []
        prefix = LoginIpBlockUtil.BLOCK_KEY_TMPL.replace('{}', '')
        keys = cache.keys(f'{prefix}*')
        for key in keys:
            ips.append(key.replace(prefix, ''))

        white_list = settings.SECURITY_LOGIN_IP_WHITE_LIST
        ips = list(set(ips) - set(white_list))
        ips = [ip for ip in ips if ip != '*']
        return ips

    def get_page_offset_and_limit(self):
        get_params = self.request.GET
        offset = get_params.get('offset', 0)
        limit = get_params.get('limit', 15)
        return int(offset), int(limit)

    def get(self, request, *args, **kwargs):
        ips = self.get_ips()
        offset, limit = self.get_page_offset_and_limit()
        slice_ips = ips[offset:offset + limit]
        results = [{'id': str(uuid4()), 'ip': ip} for ip in slice_ips]
        data = {'count': len(ips), 'results': results}
        return Response(data=data, status=200)


class UnlockIPAPI(APIView):
    perm_model = Setting
    rbac_perms = {
        'POST': 'settings.change_security'
    }

    def post(self, request):
        ips = request.data.get('ips')
        prefix = LoginIpBlockUtil.BLOCK_KEY_TMPL.replace('{}', '')
        for ip in ips:
            LoginIpBlockUtil(f'{prefix}{ip}').clean_block_if_need()
        return Response(status=200)
