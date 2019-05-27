# import json
# from datetime import datetime, timedelta
# from enum import Enum
# # from random import randint
# from tabulate import tabulate
#
# from database.domain.Databases import flows, rules

# class Levels(Enum):
#     passed = 1
#     blocked = 2


#
#
# # MAIN
# full_addr = decompress_ipv6("fe80::200:ff:fe00:1")
# print(full_addr)
# print(full_addr[4:])
# first_block = full_addr[4]
# print(hex(int(first_block, 16)))
# print(first_block[:2])
# print(first_block[2:])
# from datetime import datetime
#
# from database.domain.Databases import logs
#
# now = datetime.now()
# print(now.strftime("%d/%m/%Y %H:%M:%S"))


# db = flows
# result = db.custom_query("SELECT * FROM flows")
# result.pop(0)
# print(result)
#
# for record in result:
#     print(record[15] <= now)

# tup = ((1, "hello", 0.1234), (1, 23))
# lis = [['asdfa'], ['afsfasd']]
# if any((isinstance(i, list) or isinstance(i, tuple)) for i in tup):
#     print(True)

# print(isinstance(now, datetime))
# res = logs.custom_query("SELECT * FROM log_records WHERE date_time < \""+now+"\"")
# print(res)
# print(not res)
# record_count = len(res)
# print("Number of elements is: "+str(record_count))
# first_record = res[0]
# print("The first record is: ", first_record)
# first_record_id = first_record[0]
# print("ID of record is: ", first_record_id)
# insertion_time = first_record[1]
# print(insertion_time)
# print(res)

# testnum = 2
# testnum += randint(-1, 1)
# print(testnum)

# print(Levels.passed == Levels.blocked)

# mah_list = []
# for l in mah_list:
#     print("hi")

# my_l = [1, 1234, 123, 432, 53, 3, 6]
#
# for i in range(len(my_l)):
#     print(my_l[i])
# l = [1,2,3,4,5]

# mydict = {}
# mydict['petros'] = 10
#
# # if 'petros' in mydict.keys():
# #     print("hell yeah")
# #     number = mydict['petros']
# # else:
# #     number = None
# #
# time_now = datetime.now()
# expires_at = time_now + timedelta(seconds=60)
# print(time_now.timestamp())
# print(expires_at.timestamp())
# # print(exp_time)
# print(type(mydict.get('giannos')))
#
# print(type(str(None)))
# print(Levels.blocked.name)

# ruleset = '/home/soutzis/PycharmProjects/Janus_IPv6/blacklist.json'
#
# try:
#     with open(ruleset, "r") as f:
#         rule_dict = json.load(f)  # Get passwords from .json file as a dictionary
#         print(type(rule_dict))
# except Exception:
#     print("Could not load the admin passwords")

# db = rules
# r = rules.get_ruleset()
# print(tabulate(r, tablefmt='psql'))
#
# d = {'villos': 1}
# r['blacklist'].append(d)
# db.update_ruleset(r)

# print(type(r))
# for rule in r['blacklist']:
#     print(rule)
# r['blacklist'][0].pop('description')
# attrs = list(r['blacklist'][0].keys())
# data = [list(r['blacklist'][0].values())]
#
# print(tabulate(data, headers=attrs, tablefmt="github"))

# print("Use one of the specified values below\n")
# attrs = ['Type Description', 'Type Value']
# data = [
#     ['Destination Unreachable', 1],
#     ['Packet Too Big', 2],
#     ['Time Exceeded', 3],
#     ['Parameter Problem', 4],
#     ['Echo Request', 128],
#     ['Echo Reply', 129],
#     ['Router Solicitation', 133],
#     ['Router Advertisement', 134],
#     ['Neighbor Solicitation', 135],
#     ['Neighbor Advertisement', 136],
#     ['Redirect', 137]
# ]
# print(tabulate(data, headers=attrs, tablefmt='fancy_grid'))
# print(type(r['blacklist'][0]['priority']))
# print(136 in [item for sublist in data for item in sublist])
# result = db.custom_query("SELECT * FROM flows")
# #
# # print(tabulate(result, headers=attrs, tablefmt="psql"))
# # print(tabulate(result, headers=attrs, tablefmt="github"))
# print(tabulate(result, headers="firstrow", tablefmt="psql"))

