# -*- coding: utf-8 -*-
import json
import collections
from random import randint

def kvparsing(params):
    # foo=bar&baz=qux&zap=zazzle
    json_obj = {}
    for item in params.split("&"):
        data = item.split("=")
        json_obj[data[0]] = data[1]

    # Sort the dictionary into the correct order for challenge 13... 1 2 0
    key_order = ('email', 'uid', 'role')
    sort_json = collections.OrderedDict()
    for k in key_order:
        sort_json[k] = json_obj[k]

    return json.dumps(sort_json).encode('ascii')
    
def profile_for(user_email, role):
    if "&" in user_email:
        user_email.replace("&", "")
    if "=" in user_email:
        user_email.replace("=", "")

    uid = randint(0, 100)

    obj = kvparsing("email="+user_email+"&uid="+str(uid)+"&role="+role)
    return obj

