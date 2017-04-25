from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^register$', views.register),
    url(r'^login$', views.login),
    url(r'^logout$', views.logout),
    url(r'^secrets$', views.secrets),
    url(r'^postsecret$', views.postsecret),
    url(r'^postlike/(?P<id>\d+)$', views.postlike),
    url(r'^like/(?P<id>\d+)$', views.like),
    url(r'^delete/(?P<id>\d+)$', views.delete),
    url(r'^mostpop$', views.mostpop),
]
