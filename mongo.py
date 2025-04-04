from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017/")
db = client["nostalgia_db"]
admin_user = db.users.find_one({"email": "admin@gmail.com"})
print(admin_user)
