# from django.conf import settings

# try:
#     from PIL import Image
#     dir(Image) # Placate PyFlakes
# except ImportError:
#     import Image

# AVATAR_DEFAULT_SIZE = 48
# AUTO_GENERATE_AVATAR_SIZES = (80, 48)
# AVATAR_RESIZE_METHOD = getattr(settings, 'AVATAR_RESIZE_METHOD', Image.ANTIALIAS)
# AVATAR_STORAGE_DIR = 'avatars/groups'
# AVATAR_GRAVATAR_BACKUP = getattr(settings, 'AVATAR_GRAVATAR_BACKUP', True)
# AVATAR_GRAVATAR_DEFAULT = getattr(settings, 'AVATAR_GRAVATAR_DEFAULT', None)
# AVATAR_DEFAULT_URL = 'avatars/groups/default.png'
# AVATAR_MAX_AVATARS_PER_USER = getattr(settings, 'AVATAR_MAX_AVATARS_PER_USER', 42)
# AVATAR_MAX_SIZE = getattr(settings, 'AVATAR_MAX_SIZE', 1024 * 1024)
# AVATAR_THUMB_FORMAT = getattr(settings, 'AVATAR_THUMB_FORMAT', "JPEG")
# AVATAR_THUMB_QUALITY = getattr(settings, 'AVATAR_THUMB_QUALITY', 85)
# AVATAR_HASH_FILENAMES = getattr(settings, 'AVATAR_HASH_FILENAMES', False)
# AVATAR_HASH_USERDIRNAMES = getattr(settings, 'AVATAR_HASH_USERDIRNAMES', False)
# AVATAR_ALLOWED_FILE_EXTS = getattr(settings, 'AVATAR_ALLOWED_FILE_EXTS', None)
# AVATAR_CACHE_TIMEOUT = getattr(settings, 'AVATAR_CACHE_TIMEOUT', 60*60)
