from __future__ import unicode_literals
from django.db import models
import re


class UserManager(models.Manager):
    def validate(self, data):
        error = []
        emailreg = '[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+'
        print "Inside validate"
        if len(data['fname']) < 2 or not str.isalpha(data['fname']):
            print "inside if"
            error.append("Invalid First Name")
        if len(data['lname']) < 2 or not str.isalpha(data['lname']):
            error.append("Invalid Last Name")
        if  not re.search(emailreg, data['email']):
            error.append("Invalid Email")
        if len(data['pwd']) < 8:
            error.append("Minimum of 8 characters required for password")
        if data['pwd'] != data['conpwd']:
            error.append("Password doesn't match")
        return error

class User(models.Model):
    first_name = models.CharField(max_length=40)
    last_name = models.CharField(max_length= 40)
    email = models.CharField(max_length=40)
    password = models.CharField(max_length=40)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class Secret(models.Model):
    content = models.TextField()
    user = models.ForeignKey(User, related_name = "secretuser")
    likes = models.ManyToManyField(User, related_name = "slikes")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
