from django.conf.urls.defaults import *

# from django.views.decorators.csrf import csrf_exempt

from views import *


urlpatterns = patterns('',
    url(r'^ping/$', Ping.as_view()),
    url(r'^auth/ping/$', AuthPing.as_view()),
    url(r'^auth-token/', ObtainAuthToken.as_view()),

    url(r'^repos/$', Repos.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/$', Repo.as_view()),

)
