import os
import socketserver
import sys
import bcrypt
import json
import secrets
from pymongo import MongoClient
import hashlib
from util.request import Request

class MyTCPHandler(socketserver.BaseRequestHandler):
    # mongoclient = MongoClient("mongo") for docker

    def handle(self):
        received_data = self.request.recv(2048)
        # print(self.client_address)
        # print("--- received data ---")
        # print(received_data)
        # print("--- end of data ---\n\n")
        request = Request(received_data)
        # print(request.method +" method is printed")
        # print(request.path + " path is printed")
        # print(request.http_version + "  version is printed")
        # print(request.headers)
        mongoclient = MongoClient("mongo")
        # mongoclient = MongoClient("localhost")
        db = mongoclient["cse312"]
        chat_collection = db["chat"]
        user_collection = db["users"]

        # TODO: Parse the HTTP request and use self.request.sendall(response) to send your response
        #divide the headers from the body
        #subdivide with \r\n for the headers
        #divide the first header line using spaces to get the path and other stuff
        pictures = os.listdir('public/image')
        for i in range(len(pictures)):
            pictures[i] = "/public/image/" + pictures[i]

        if request.path == "/":
            index = open("public/index.html", "rb")
            read = index.read()
            indexLength = len(read)
            read = read.decode()
            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/html; charset=utf-8" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n"+"X-Content-Type-Options: nosniff""\r\n\r\n" + read
            responseString = responseString.strip()
            # print(responseString)
            self.request.sendall(responseString.encode())

        # print(request.path + " this os request")
        elif request.path == "/public/style.css":
            index = open("public/style.css", "rb")
            read = index.read()
            indexLength = len(read)
            # print(request.http_version)
            read = read.decode()
            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/css; charset=utf-8" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n"+"X-Content-Type-Options: nosniff""\r\n\r\n" + read
            responseString = responseString.strip()
            self.request.sendall(responseString.encode())

        elif request.path == "/public/functions.js":
            index = open("public/functions.js","rb")
            read = index.read()
            indexLength = len(read)
            # print(indexLength) #2467
            read = read.decode()
            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/javascript; charset=utf-8" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n"+"X-Content-Type-Options: nosniff""\r\n\r\n" + read
            responseString = responseString.strip()
            self.request.sendall(responseString.encode())


        elif request.path in pictures:
            index = open(request.path[1:], "rb").read()
            indexLength = len(index)
            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: image/jpeg" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n" + "X-Content-Type-Options: nosniff" + "\r\n\r\n"
            # print(responseString)
            responseString = responseString.encode()
            responseString += index
            # print(responseString)
            self.request.sendall(responseString)

        elif request.path in "/favicon.ico":
            index = open("public/image/kitten.jpg", "rb").read()
            indexLength = len(index)
            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: image/jpeg" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n" + "X-Content-Type-Options: nosniff" + "\r\n\r\n"
            # print(responseString)
            responseString = responseString.encode()
            responseString += index
            # print(responseString)
            self.request.sendall(responseString)

        elif request.path == "/visit-counter":
            # print("it runs")
            text = "Cookies: "

            cookieheader = request.headers.get("Cookie")
            visitHeader = cookieheader
            visitNum = 1
            if cookieheader != None:
                cookieheader = cookieheader.split(";")
                print(cookieheader)
                for cookie in cookieheader:
                    cookie = cookie.split("=")
                    if cookie[0] == " visits" or cookie[0] == "visits":
                        visitNum = int(cookie[1]) +1
                        break
            else:
                visitNum = 1
            text += str(visitNum)
            textLen = len(text)
            # print(textLen)
            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/plain; charset=utf-8" + "\r\n" + "Content-Length: " + str(textLen) + "\r\n" + "X-Content-Type-Options: nosniff" + "\r\n" +"Set-Cookie: visits=" +str(visitNum)+ ";Max-Age =3600;" +"\r\n\r\n" +text
            # responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/plain; charset=utf-8" + "\r\n" + "Content-Length: " + str(textLen) + "\r\n" + "X-Content-Type-Options: nosniff"  +"\r\n\r\n" +text
            self.request.sendall(responseString.encode())

        elif request.path == "/chat-message":
            #if I get a get post request send mess3ge if the the request is a delete delete messge

                message = json.loads(request.body.decode())["message"]
                message = message.replace("&","&amp;")
                message = message.replace("<","&lt;")
                message = message.replace(">","&gt;")
                # print(request.headers)
                #
                hol = False
                print(request.headers)
                cookieheader = request.headers.get("Cookie")
                print(cookieheader)
                if cookieheader != None:
                    cookieheader = cookieheader.split(";")
                    print(cookieheader)
                    for cookie in cookieheader:
                        cookie = cookie.split("=")
                        print("cookiies: "+ str(cookie))
                        if cookie[0] == "Auth" or cookie[0] == " Auth":
                            # bcrypt.checkpw(password.encode(), user_collection.find_one({"username": username})["password"]):
                            user = user_collection.find_one({"Auth": cookie[1]})
                            print("got user using cookie:"+ str(user))
                            chat_collection.insert_one({"username": user["username"], "message": message})
                            hol = True
                if hol == False:
                    print("guest")
                    chat_collection.insert_one({"username": "Guest", "message": message})
                text = "ok"
                textLen = len(text.encode())
                responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/plain; charset=utf-8" + "\r\n" + "Content-Length: " + str(textLen) + "\r\n" + "X-Content-Type-Options: nosniff" +"\r\n\r\n" +text
                self.request.sendall(responseString.encode())

        elif request.path == "/register":
            #get the username and the password from the encoded url whcih will be in the body of the request
            body = request.body.decode()
            #inputted hello and hi for username and password
            # username_reg=hello&password_reg=hi
            # print(request.headers["Content-Length"])
            length = request.headers["Content-Length"]
            username = body.split("&")[0].split("=")[1]
            print(username)
            #gotta make sure it checks for duplicate username before adding this one
            password =  body.split("&")[1].split("=")[1]
            print(password)
            salt = bcrypt.gensalt()
            encodedPassword = password.encode()
            hashedPassword = bcrypt.hashpw(encodedPassword,salt)
            # auth = b""
            user_collection.insert_one({"username": username,"password":hashedPassword,"Auth": None})



        elif request.path == "/login":
            #get the username and the password from the encoded url whcih will be in the body of the request
            body = request.body.decode()
            #inputted hello and hi for username and password
            # username_reg=hello&password_reg=hi
            # print(request.headers["Content-Length"])
            length = request.headers["Content-Length"]
            username = body.split("&")[0].split("=")[1]
            print(username)
            password = body.split("&")[1].split("=")[1]
            print(password)
            if user_collection.find_one({"username": username}) == None:
                print("user not foound")
            # print(user_collection.find_one({"username": username})["password"])
            elif bcrypt.checkpw(password.encode(),user_collection.find_one({"username": username})["password"]):
                print("logged in")
                authtoken = secrets.token_bytes()
                print("token: " + str(authtoken))
                # sha256 = hashlib.sha256(authtoken).digest()
                # authTokenHash = sha256.update(authtoken)
                authTokenHash = hashlib.sha256(authtoken).hexdigest()
                print("hashed: "  +str(authTokenHash))
                # use find
                user_collection.find_one({"username": username})
                user_collection.update_one({"username":username}, {"$set":{"Auth": authTokenHash}})
                index = open("public/index.html", "rb")
                read = index.read()
                indexLength = len(read)
                read = read.decode()
                responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/html; charset=utf-8" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n"+"X-Content-Type-Options: nosniff"+ "\r\n" +"Set-Cookie:Auth=" + str(authTokenHash) + ";Max-Age =7200;HttpOnly;" "\r\n\r\n" + read
                responseString = responseString.strip()
                # print(responseString)
                # print(responseString)
                self.request.sendall(responseString.encode())

        elif request.path == "/chat-history":
            index = chat_collection.find()
            chatArray = []
            for message in index:
                # print(message)
                chatArray.append({"username": message['username'], "id": str(message['_id']), "message": message["message"]})
            # print(chatArray)
            indexJson = json.dumps(chatArray)
            indexJson.encode()
            length = len(indexJson)
            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: application/json; charset=utf-8" + "\r\n" + "Content-Length: " + str(length) + "\r\n" + "X-Content-Type-Options: nosniff" +"\r\n\r\n" + indexJson
            self.request.sendall(responseString.encode())

        chat = chat_collection.find({})
        for mess in chat:
            # print(mess["_id"])
            hol = False
            if request.path == "/chat-message/" + str(mess["_id"]):
                # print("this is the request path:" + request.path)
                # print("/chat-message/" + str(mess["_id"]))
                # print(request.http_version)
                # if request.method == "DELETE":
                cookieheader = request.headers.get("Cookie")
                # print(request.headers)
                if cookieheader != None:
                    cookieheader = cookieheader.split(";")
                    # print(cookieheader)
                    for cookie in cookieheader:
                        cookie = cookie.split("=")
                        # print("cookiies: " + str(cookie))
                        if cookie[0] == "Auth" or cookie[0] == " Auth":
                            hol = True
                            user = user_collection.find_one({"Auth": cookie[1]})
                            # print("got user using cookie:" + str(user["username"]))
                            # print(mess["_id"])
                            currMess = chat_collection.find_one({"_id": mess["_id"]})
                            # print(currMess)
                            if currMess["username"] == user["username"]:
                                chat_collection.delete_one({"_id": mess["_id"]})
                                print("deleted")
                                text = "ok"
                                textLen = len(text.encode())
                                responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/plain; charset=utf-8" + "\r\n" + "Content-Length: " + str(
                                    textLen) + "\r\n" + "X-Content-Type-Options: nosniff" + "\r\n\r\n" + text
                                self.request.sendall(responseString.encode())
                            else:
                                print("forbid")
                                text = "Not your message"
                                text.encode()
                                textLen = len(text)
                                responseString = "" + request.http_version + " 403 Forbidden" + "\r\n" + "Content-Type: text/plain; charset=utf-8" + "\r\n" + "Content-Length: " + str(textLen) + "\r\n" + "X-Content-Type-Options: nosniff" + "\r\n\r\n" + text
                                self.request.sendall(responseString.encode())



        else:
            text = "content not found"
            textLen = len(text.encode())
            # print(textLen)
            responseString = "" + request.http_version + " 404 Not Found" + "\r\n" + "Content-Type: text/plain; charset=utf-8" + "\r\n" + "Content-Length: " + str(textLen) + "\r\n" + "X-Content-Type-Options: nosniff" +"\r\n\r\n" +text
            # print(responseString)
            self.request.sendall(responseString.encode())


def main():
    host = "0.0.0.0"
    port = 8000
    # port = 8080

    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.TCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    sys.stdout.flush()
    sys.stderr.flush()

    server.serve_forever()


if __name__ == "__main__":
    # GET /form-path?commenter=Jesse&comment=Good+Morning%21 HTTP/1.1
    # sample_request = b'POST /chat-message HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello'
    sample_request = b'DELETE /chat-message/652ce3ac5d3eca910989e991 HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n'
    request = Request(sample_request)
    assert request.method == "DELETE"
    # print(request.path)
    assert request.path == "/chat-message/652ce3ac5d3eca910989e991"
    # print(request.body)
    # assert request.body.decode() == "hello"

    main()