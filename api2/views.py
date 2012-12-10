# encoding: utf-8
from rest_framework import parsers
from rest_framework import status
from rest_framework import renderers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from models import Token
from authentication import TokenAuthentication
from serializers import AuthTokenSerializer
from base.accounts import User
from seahub.views import access_to_repo, validate_owner

from seaserv import seafserv_threaded_rpc, get_personal_groups_by_user, \
    get_group_repos, get_repo, check_permission, get_commits

class Ping(APIView):
    """
    Returns a simple `pong` message when client calls `api2/ping/`.
    For example:
    	curl http://127.0.0.1:8000/api2/ping/
    """
    def get(self, request, format=None):
        return Response('pong')

class AuthPing(APIView):
    """
    Returns a simple `pong` message when client provided an auth token.
    For example:
    	curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" http://127.0.0.1:8000/api2/auth/ping/
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, format=None):
        return Response('pong')

class ObtainAuthToken(APIView):
    """
    Returns auth token if username and password are valid.
    For example:
    	curl -d "username=xiez1989@gmail.com&password=123456" http://127.0.0.1:8000/api2/auth-token/
    """
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,) 
    model = Token

    def post(self, request):
        serializer = AuthTokenSerializer(data=request.DATA)
        if serializer.is_valid():
            token, created = Token.objects.get_or_create(user=serializer.object['user'].username)
            return Response({'token': token.key})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def calculate_repo_info(repo_list, username):
    """
    Get some info for repo.

    """
    for repo in repo_list:
        try:
            commit = get_commits(repo.id, 0, 1)[0]
            repo.latest_modify = commit.ctime
            repo.root = commit.root_id
            repo.size = seafserv_threaded_rpc.server_repo_size(repo.id)
            if not repo.size :
                repo.size = 0;

            password_need = False
            if repo.encrypted:
                try:
                    ret = seafserv_rpc.is_passwd_set(repo.id, username)
                    if ret != 1:
                        password_need = True
                except SearpcErroe, e:
                    pass
            repo.password_need = password_need
        except Exception,e:
            repo.latest_modify = 0
            repo.commit = None
            repo.size = -1
            repo.password_need = None
    
class Repos(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        email = request.user.username

        owned_repos = seafserv_threaded_rpc.list_owned_repos(email)
        calculate_repo_info (owned_repos, email)
        owned_repos.sort(lambda x, y: cmp(y.latest_modify, x.latest_modify))

        n_repos = seafserv_threaded_rpc.list_share_repos(email,
                                                         'to_email', -1, -1)
        calculate_repo_info (n_repos, email)
        owned_repos.sort(lambda x, y: cmp(y.latest_modify, x.latest_modify))

        repos_json = []
        for r in owned_repos:
            repo = {
                "type":"repo",
                "id":r.id,
                "owner":email,
                "name":r.name,
                "desc":r.desc,
                "mtime":r.latest_modify,
                "root":r.root,
                "size":r.size,
                "encrypted":r.encrypted,
                "password_need":r.password_need,
                }
            repos_json.append(repo)

        for r in n_repos:
            repo = {
                "type":"srepo",
                "id":r.id,
                "owner":r.shared_email,
                "name":r.name,
                "desc":r.desc,
                "mtime":r.latest_modify,
                "root":r.root,
                "size":r.size,
                "encrypted":r.encrypted,
                "password_need":r.password_need,
                }
            repos_json.append(repo)

        groups = get_personal_groups_by_user(email)
        for group in groups:
            g_repos = get_group_repos(group.id, email)
            calculate_repo_info (g_repos, email)
            owned_repos.sort(lambda x, y: cmp(y.latest_modify, x.latest_modify))
            for r in g_repos:
                repo = {
                    "type":"grepo",
                    "id":r.id,
                    "owner":group.group_name,
                    "name":r.name,
                    "desc":r.desc,
                    "mtime":r.latest_modify,
                    "root":r.root,
                    "size":r.size,
                    "encrypted":r.encrypted,
                    "password_need":r.password_need,
                    }
                repos_json.append(repo)

        return Response(repos_json)

def can_access_repo(request, repo_id):
    if not check_permission(repo_id, request.user.username):
        return False
    return True
    
class Repo(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def get(self, request, repo_id, format=None):
        # check whether user can view repo
        repo = get_repo(repo_id)
        if not repo:
            # return api_error(request, '404')
            return Response(status.HTTP_404_NOT_FOUND)

        if not can_access_repo(request, repo.id):
            # return api_error(request, '403')
            return Response(status.HTTP_403_FORBIDDEN)

        # check whether use is repo owner
        if validate_owner(request, repo_id):
            owner = "self"
        else:
            owner = "share"

        try:
            repo.latest_modify = get_commits(repo.id, 0, 1)[0].ctime
        except:
            repo.latest_modify = None

        # query repo infomation
        repo.size = seafserv_threaded_rpc.server_repo_size(repo_id)
        current_commit = get_commits(repo_id, 0, 1)[0]
        repo_json = {
            "type":"repo",
            "id":repo.id,
            "owner":owner,
            "name":repo.name,
            "desc":repo.desc,
            "mtime":repo.lastest_modify,
            "size":repo.size,
            "encrypted":repo.encrypted,
            "root":current_commit.root_id,
            "password_need":repo.password_need,
            }

        return Response(repo_json)

    def post(self, request, repo_id, format=None):
        # TODO
        pass
