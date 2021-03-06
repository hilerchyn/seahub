# encoding: utf-8
import simplejson as json
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response, get_object_or_404
from django.template import Context, RequestContext
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.translation import ugettext as _

from seaserv import ccnet_rpc, ccnet_threaded_rpc, get_binding_peerids
from pysearpc import SearpcError

from forms import ProfileForm
from models import Profile
from utils import refresh_cache
from seahub.utils import render_error
from seahub.base.accounts import User
from seahub.contacts.models import Contact


@login_required
def edit_profile(request):
    """
    Show and edit user profile.
    """
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        if form.is_valid():
            nickname = form.cleaned_data['nickname']
            intro = form.cleaned_data['intro']
            try:
                profile = Profile.objects.get(user=request.user.username)
            except Profile.DoesNotExist:
                profile = Profile()
                
            profile.user = request.user.username
            profile.nickname = nickname
            profile.intro = intro
            profile.save()
            messages.success(request, _(u'Successfully edited profile.'))
            # refresh nickname cache
            refresh_cache(request.user.username)
            
            return HttpResponseRedirect(reverse('edit_profile'))
        else:
            messages.error(request, _(u'Failed to edit profile'))
    else:
        try:
            profile = Profile.objects.get(user=request.user.username)
            form = ProfileForm({
                    'nickname': profile.nickname,
                    'intro': profile.intro,
                    })
        except Profile.DoesNotExist:
            form = ProfileForm()

    return render_to_response('profile/set_profile.html', {
            'form': form,
            }, context_instance=RequestContext(request))

@login_required
def user_profile(request, user):
    user_nickname = ''
    user_intro = ''

    try:
        user_check = User.objects.get(email=user)
    except User.DoesNotExist:
        user_check = None
        
    if user_check:
        profile = Profile.objects.filter(user=user)
        if profile:
            profile = profile[0]
            user_nickname = profile.nickname
            user_intro = profile.intro
    else:
        nickname = user
        user_intro = _(u'Has not accepted invitation yet')

    if user == request.user.username or \
            Contact.objects.filter(user_email=request.user.username,
                                   contact_email=user).count() > 0:
        new_user = False
    else:
        new_user = True
    print new_user
    return render_to_response('profile/user_profile.html', {
            'email': user,
            'nickname': user_nickname,
            'intro': user_intro,
            'new_user': new_user,
            }, context_instance=RequestContext(request))

@login_required
def get_user_profile(request, user):
    data = {
            'email': user,
            'user_nickname': '',
            'user_intro': '',
            'err_msg': '',
            'new_user': ''
        } 
    content_type = 'application/json; charset=utf-8'

    try:
        user_check = User.objects.get(email=user)
    except User.DoesNotExist:
        user_check = None
        
    if user_check:
        profile = Profile.objects.filter(user=user)
        if profile:
            profile = profile[0]
            data['user_nickname'] = profile.nickname
            data['user_intro'] = profile.intro
    else:
        data['user_intro'] = _(u'Has not accepted invitation yet')

    if user == request.user.username or \
            Contact.objects.filter(user_email=request.user.username,
                                   contact_email=user).count() > 0:
        data['new_user'] = False
    else:
        data['new_user'] = True

    return HttpResponse(json.dumps(data), content_type=content_type)
