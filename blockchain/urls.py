from django.contrib import admin
from django.urls import path

from . import views

urlpatterns = [
    path('', views.show_result, name='show-result'),
    path('vote/', views.home, name='blockchain'),
    path('authentication/', views.authentication, name='authentication'),
    path('get-parties/', views.get_parties, name='get-parties'),
    path('create-vote/', views.create_vote, name='create-vote'),
    path('create-dummy-data/', views.create_dummy_data, name='create-dummy-data'),
    path('result/', views.show_result, name='show-result'),
    path('mine-block/', views.mine_block, name='mine-block'),
    path('start-mining/', views.start_mining, name='start-mining'),
    path('blocks/', views.blockchain, name='blockchain'),
    path('block-info/', views.block_info, name='block-info'),
    path('sync-block/', views.sync_block, name='sync-block'),
    path('verify-block/', views.verify_block, name='verify-block'),
    path('track-server/', views.track_server, name='track-server'),
    path('validate/', views.validate_authority, name='validate'),
    path('verify_key/', views.verify_key, name='verify_key'),
    path('authenticate_email/', views.authenticate_email, name='authenticate_email'),

]