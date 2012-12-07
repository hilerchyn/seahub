# encoding: utf-8
# Django settings for seahub project.
import os

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS

install_topdir = os.path.expanduser(os.path.join(os.path.dirname(__file__), '../..'))

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME' : os.path.join(install_topdir, 'seahub.db')
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'Asia/Shanghai'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = os.path.join(os.path.dirname(__file__), "media")

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
MEDIA_URL = '/media/'

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

ADMIN_MEDIA_PREFIX = '%sadmin/' %(MEDIA_URL)

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'n*v0=jz-1rz@(4gx^tf%6^e7c&um@2)g-l=3_)t@19a69n1nv6'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.csrf.CsrfResponseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',    
    'auth.middleware.AuthenticationMiddleware',
    'base.middleware.BaseMiddleware',    
    'base.middleware.InfobarMiddleware',
    'seahub.subdomain.middleware.SubdomainMiddleware',
)

SITE_ROOT_URLCONF = 'seahub.urls'
ROOT_URLCONF = 'djblets.util.rooturl'
 
SITE_ROOT = '/'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    os.path.join(os.path.dirname(__file__), "templates"),
    os.path.join(os.path.dirname(__file__),'thirdpart/djangorestframework/templates'),
)

# This is defined here as a do-nothing function because we can't import
# django.utils.translation -- that module depends on the settings.
gettext_noop = lambda s: s
LANGUAGES = (
    ('en', gettext_noop('English')),
    ('zh-cn', gettext_noop(u'简体中文')),
)
LOCALE_PATHS = (
    os.path.join(os.path.dirname(__file__), 'locale'),
    os.path.join(os.path.dirname(__file__), 'thirdpart/auth/locale'),
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.core.context_processors.auth',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'djblets.util.context_processors.siteRoot',
    'django.core.context_processors.request',
    'django.contrib.messages.context_processors.messages',
    'seahub.base.context_processors.base',
#    'seahub.organizations.context_processors.org',
)


INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.sessions',
#    'django.contrib.sites',
#    'django.contrib.admin',
    'django.contrib.messages',
    
    # 'auth',
    'avatar',    
    'registration',

    'seahub.base',
    'seahub.contacts',
    'seahub.group',    
    'seahub.notifications',
    'seahub.organizations',
    'seahub.profile',
    'seahub.share',
    'seahub.subdomain',
    'seahub.api',
    'gunicorn',
)

AUTHENTICATION_BACKENDS = (
    'auth.backends.ModelBackend',
)

ACCOUNT_ACTIVATION_DAYS = 7

# File preview
FILE_PREVIEW_MAX_SIZE = 10 * 1024 * 1024

# Avatar
AVATAR_STORAGE_DIR = 'avatars'
GROUP_AVATAR_STORAGE_DIR = 'avatars/groups'
AVATAR_GRAVATAR_BACKUP = False
AVATAR_DEFAULT_URL = '/avatars/default.jpg'
AVATAR_DEFAULT_NON_REGISTERED_URL = '/avatars/default-non-register.jpg'
GROUP_AVATAR_DEFAULT_URL = 'avatars/groups/default.png'
AVATAR_MAX_AVATARS_PER_USER = 1
AVATAR_CACHE_TIMEOUT = 24 * 60 * 60
AVATAR_ALLOWED_FILE_EXTS = ('.jpg', '.png', '.jpeg', '.gif')
AUTO_GENERATE_AVATAR_SIZES = (16, 20, 28, 40, 48, 60, 80)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/tmp/seahub_cache',
    }
}

MAX_UPLOAD_FILE_SIZE        = 100 * 1024 * 1024 # 100 MB
MAX_UPLOAD_FILE_NAME_LEN    = 256

# Set to True when user will be activaed after registration,
# and no email sending
ACTIVATE_AFTER_REGISTRATION = True

# In order to use email sending,
# ACTIVATE_AFTER_REGISTRATION MUST set to False
REGISTRATION_SEND_MAIL = False

# Seafile httpserver address and port
HTTP_SERVER_ROOT = "http://localhost:8082"

# Seafile-applet address and port, used in repo download
CCNET_APPLET_ROOT = "http://localhost:13420"

# Account initial password, for password resetting.
INIT_PASSWD = '123456'

# browser tab title
SITE_TITLE = 'Private Seafile'

# Base url and name used in email sending
SITE_BASE = 'http://seafile.com'
SITE_NAME = 'Seafile'

# Using Django to server static file. Set to `False` if deployed behide a web
# server.
SERVE_STATIC = True

try:
    import sys
    sys.path.insert(0, install_topdir)
    import seahub_settings as local_settings
except ImportError:
    pass
else:
  # Import any symbols that begin with A-Z. Append to lists any symbols that
  # begin with "EXTRA_".
    import re
    for attr in dir(local_settings):
        match = re.search('^EXTRA_(\w+)', attr)
        if match:
            name = match.group(1)
            value = getattr(local_settings, attr)
            try:
                globals()[name] += value
            except KeyError:
                globals()[name] = value
        elif re.search('^[A-Z]', attr):
            globals()[attr] = getattr(local_settings, attr)

LOGIN_URL = SITE_ROOT + 'accounts/login'

SEAFILE_VERSION = '1.3.0'

USE_SUBDOMAIN = False

