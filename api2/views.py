# encoding: utf-8
import stat
import seahub.settings as settings

from rest_framework import parsers
from rest_framework import status
from rest_framework import renderers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.sites.models import RequestSite

from models import Token
from mime import get_file_mime
from authentication import TokenAuthentication
from serializers import AuthTokenSerializer
from base.accounts import User
from share.models import FileShare
from seahub.views import access_to_repo, validate_owner
from seahub.utils import gen_file_get_url, gen_token

from pysearpc import SearpcError
from seaserv import seafserv_rpc, seafserv_threaded_rpc, \
    get_personal_groups_by_user, \
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

HTTP_ERRORS = {
    '400':'Bad arguments',
    '401':'Login required',
    '402':'Incorrect repo password',
    '403':'Can not access repo',
    '404':'Repo not found',
    '405':'Query password set error',
    '406':'Repo is not encrypted',
    '407':'Method not supported',
    '408':'Login failed',
    '409':'Repo password required',
    '410':'Path does not exist',
    '411':'Failed to get dirid by path',
    '412':'Failed to get fileid by path',
    '413':'Above quota',
    '415':'Operation not supported',
    '416':'Failed to list dir',
    '417':'Set password error',
    '418':'Failed to delete',
    '419':'Failed to move',
    '420':'Failed to rename',
    '421':'Failed to mkdir',

    '499':'Unknow Error',

    '500':'Internal server error',
    '501':'Failed to get shared link',
    '502':'Failed to send shared link',
}

def api_error(code='499', msg=None):
    err_resp = {'error_msg': msg if msg else HTTP_ERRORS[code]}
    return Response(err_resp, status=code)

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
            return api_error('404')

        if not can_access_repo(request, repo.id):
            return api_error('403')

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

def check_repo_access_permission(request, repo):
    if not repo:
        return api_error('404')

    if not can_access_repo(request, repo.id):
        return api_error('403')

    password_set = False
    if repo.encrypted:
        try:
            ret = seafserv_rpc.is_passwd_set(repo.id, request.user.username)
            if ret == 1:
                password_set = True
        except SearpcError, e:
            return api_error('405', "SearpcError:" + e.msg)

        if not password_set:
            password = request.REQUEST.get('password', default=None)
            if not password:
                return api_error('409')

            return set_repo_password(request, repo, password)

def get_file_size (id):
    size = seafserv_threaded_rpc.get_file_size(id)
    return size if size else 0

def get_dir_entrys_by_id(request, dir_id):
    dentrys = []
    try:
        dirs = seafserv_threaded_rpc.list_dir(dir_id)
    except SearpcError, e:
        return api_error("416")

    for dirent in dirs:
        dtype = "file"
        entry={}
        if stat.S_ISDIR(dirent.mode):
            dtype = "dir"
        else:
            mime = get_file_mime(dirent.obj_name)
            if mime:
                entry["mime"] = mime
            try:
                entry["size"] = get_file_size(dirent.obj_id)
            except Exception, e:
                entry["size"]=0

        entry["type"]=dtype
        entry["name"]=dirent.obj_name
        entry["id"]=dirent.obj_id
        dentrys.append(entry)
    return Response(dentrys)
    # response = HttpResponse(json.dumps(dentrys), status=200,
    #                         content_type=json_content_type)
    # response["oid"] = dir_id
    # return response
        
class RepoDirents(APIView):
    """
    List directory entries of a repo.
    TODO: may be better use dirent id instead of path.
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, repo_id):
        repo = get_repo(repo_id)
        resp = check_repo_access_permission(request, repo)
        if resp:
            return resp

        current_commit = get_commits(repo_id, 0, 1)[0]
        path = request.GET.get('p', '/')
        if path[-1] != '/':
            path = path + '/'

        dir_id = None
        try:
            dir_id = seafserv_threaded_rpc.get_dirid_by_path(current_commit.id,
                                                             path.encode('utf-8'))
        except SearpcError, e:
            return api_error("411", "SearpcError:" + e.msg)

        if not dir_id:
            return api_error('410')

        old_oid = request.GET.get('oid', None)
        if old_oid and old_oid == dir_id :
            response = HttpResponse(json.dumps("uptodate"), status=200,
                                    content_type=json_content_type)
            response["oid"] = dir_id
            return response
        else:
            return get_dir_entrys_by_id(request, dir_id)
    
class RepoDirs(APIView):
    """
    List directory entries based on dir_id.
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def get(self, request, repo_id, dir_id, format=None):
        repo = get_repo(repo_id)
        resp = check_repo_access_permission(request, repo)
        if resp:
            return resp

        return get_dir_entrys_by_id(request, dir_id)

def get_shared_link(request, repo_id, path):
    l = FileShare.objects.filter(repo_id=repo_id).filter(\
        username=request.user.username).filter(path=path)
    token = None
    if len(l) > 0:
        fileshare = l[0]
        token = fileshare.token
    else:
        token = gen_token(max_length=10)

        fs = FileShare()
        fs.username = request.user.username
        fs.repo_id = repo_id
        fs.path = path
        fs.token = token

        try:
            fs.save()
        except IntegrityError, e:
            return api_err('501')

    domain = RequestSite(request).domain
    file_shared_link = 'http://%s%sf/%s/' % (domain,
                                             settings.SITE_ROOT, token)
    return Response(file_shared_link)
    
def get_repo_file(request, repo_id, file_id, file_name, op):
    if op == 'download':
        token = seafserv_rpc.web_get_access_token(repo_id, file_id,
                                                  op, request.user.username)
        redirect_url = gen_file_get_url(token, file_name)
        return Response(redirect_url)
        # response = HttpResponse(json.dumps(redirect_url), status=200,
        #                         content_type=json_content_type)
        # response["oid"] = file_id
        # return response

    if op == 'sharelink':
        path = request.GET.get('p', None)
        assert path, 'path must be passed in the url'
        return get_shared_link(request, repo_id, path)
    
class RepoFiles(APIView):
    """
    
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def get(self, request, repo_id, file_id, format=None):
        repo = get_repo(repo_id)
        resp = check_repo_access_permission(request, repo)
        if resp:
            return resp

        file_name = request.GET.get('file_name', file_id)
        return get_repo_file(request, repo_id, file_id, file_name, 'download')
        
