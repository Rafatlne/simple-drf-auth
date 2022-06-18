import logging

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .manager import UserManager

logger = logging.getLogger(__name__)


from django.db import models


class BaseModel(models.Model):
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey("user.User", null=True, editable=False,
                                   related_name="%(app_label)s_%(class)s_created", on_delete=models.CASCADE)
    updated_by = models.ForeignKey("user.User", null=True, editable=False,
                                   related_name="%(app_label)s_%(class)s_updated", on_delete=models.CASCADE)

    class Meta:
        abstract = True
        

class User(AbstractBaseUser, PermissionsMixin, BaseModel):
    USER_TYPE_CHOICE = (
        ('admin', "Admin"),
        ('passenger', "Passenger")
    )

    first_name = models.CharField(_('first name'), max_length=150, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    email = models.EmailField(_('email address'), blank=True, unique=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    user_type = models.CharField(_('user type'), choices=USER_TYPE_CHOICE, default='admin', max_length=30)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'

    objects = UserManager()

    def __str__(self):
        return self.email

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    @property
    def full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()