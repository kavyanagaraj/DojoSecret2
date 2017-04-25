from django.shortcuts import render, redirect, HttpResponse
from .models import User, Secret
from django.contrib import messages
from django.db.models import Count
from django.core.urlresolvers import reverse
import bcrypt

def index(request):
    return render(request, "index.html")

def secrets(request):
    secrets = Secret.objects.all().order_by('-created_at')
    context ={
    "user" : User.objects.get(id = request.session['uid']),
    "secrets" : secrets[:5]
    }
    return render(request, "secret.html", context)

def postsecret(request):
    secret = request.POST['secret']
    user = User.objects.get(id = request.session['uid'])
    secret = Secret.objects.create(content = secret, user = user)
    return redirect('/secrets')

def postlike(request,id):
    secret = Secret.objects.get(id = id)
    user = User.objects.get(id = request.session['uid'])
    secret.likes.add(user)
    return redirect('/secrets')

def delete(request, id):
    secret = Secret.objects.get(id = id)
    secret.delete()
    return redirect('/secrets')

def mostpop(request):
    secrets = Secret.objects.all().annotate(numLikes = Count('likes')).order_by('-numLikes')
    secrets = secrets
    context ={
    "user" : User.objects.get(id = request.session['uid']),
    "secrets" : secrets
    }
    return render(request, "mostpop.html", context)

def like(request,id):
    secret = Secret.objects.get(id = id)
    user = User.objects.get(id = request.session['uid'])
    secret.likes.add(user)
    return redirect('/mostpop')

def register(request):
    request.session['login'] = False
    print request.session['login']
    fname = str(request.POST['first_name'])
    lname = str(request.POST['last_name'])
    email = str(request.POST['email'])
    pwd = request.POST['password'].encode()
    conpwd = request.POST['confirm_password'].encode()
    context = {
    "fname" : fname,
    "lname" : lname,
    "email" : email,
    "pwd" : pwd,
    "conpwd" : conpwd
    }
    if  User.objects.all().filter(email = email):
        messages.add_message(request, messages.INFO, "Email already exists! Please login")
        return redirect('/')
    error = User.objects.validate(context)
    if error:
        for ele in error:
            messages.add_message(request, messages.ERROR, ele)
        return redirect('/')
    else:
        hashedpwd = bcrypt.hashpw(pwd, bcrypt.gensalt())
        user = User.objects.create(first_name = fname, last_name = lname, email = email, password = hashedpwd)
        request.session['uid'] = user.id
        return redirect('/secrets')

def login(request):
    request.session['login'] = True
    print request.session['login']
    email = str(request.POST['email'])
    pwd = request.POST['password'].encode()
    user = User.objects.all().filter(email = email)
    if  not user:
        messages.add_message(request, messages.INFO, "Email doesn't exist! Please register")
        return redirect('/')
    else:
        if user[0].password != bcrypt.hashpw(pwd, (user[0].password).encode()):
            messages.add_message(request, messages.INFO, "Invalid password")
            return redirect('/')
        else:
            request.session['uid'] = user[0].id
            return redirect('/secrets')

def logout(request):
    request.session.clear()
    return redirect('/')
