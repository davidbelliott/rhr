from peewee import *

from rhr import User, Like

for user in User.select():
    if user.password_hash != '':
        if user.registered:
            print(user.name, "signed up for an account")
        else:
            print(user.name, "signed up BUT IS NOT REGISTERED")

for like in Like.select():
    if like.notified:
        print("{} MATCHED WITH {}".format(like.liker.name, like.liked.name))
    else:
        print("{} likes {}".format(like.liker.name, like.liked.name))
