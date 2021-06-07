import json

# some JSON:
x = '{ "name":"John", "age":30, "city":"New York"}'

# parse x:
y = json.loads(x)

# the result is a Python dictionary:
<<<<<<< HEAD
print(y["name"])
print(x)
=======
print(y["age"])
>>>>>>> 3879c18c64c4e5ea91330adf9f5ada154a953344
