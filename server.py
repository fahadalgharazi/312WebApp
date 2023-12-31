import os
import socketserver
import sys
import bcrypt
import json
import secrets
from pymongo import MongoClient
import hashlib

from util.buff import Buffer
from util.request import Request
from util.sockParse import SockParse

import base64

class MyTCPHandler(socketserver.BaseRequestHandler):
    # mongoclient = MongoClient("mongo") for docker
    counter = 0
    websocket_connections = []
    def handle(self):
            # while True:
        # MyTCPHandler.counter += 1
        received_data = self.request.recv(2048)
        if len(received_data) == 0:
            return
        request = Request(received_data)
        # MyTCPHandler.websocket_connections.append(self)
        # mongoclient = MongoClient("mongo")
        mongoclient = MongoClient("localhost")
        db = mongoclient["cse312"]
        chat_collection = db["chat"]
        user_collection = db["users"]
        # received_data = self.request.recv(2048)
        # print(received_data)

    # TODO: Parse the HTTP request and use self.request.sendall(response) to send your response

        pictures = os.listdir('public/image')
        for i in range(len(pictures)):
            pictures[i] = "/public/image/" + pictures[i]

        if request.path == "/":
            index = open("public/index.html", "rb")
            read = index.read()
            indexLength = len(read)
            read = read.decode()
            ########login
            cookieheader = request.headers.get("Cookie")
            # print("profiel pic")
            if cookieheader != None:
                cookieheader = cookieheader.split(";")
                # print(cookieheader)
                for cookie in cookieheader:
                    cookie = cookie.split("=")
                    # print("cookiies: " + str(cookie))
                    if cookie[0] == "Auth" or cookie[0] == " Auth":
                        # print("user logged in")
                        ##save the file into the disk
                        # user_collection
                        userCookie = cookie[1]
                        for user in user_collection.find({}):
                            if user["Auth"] == userCookie:
                                username = user["username"]
                                # print("inside if "+user["pic"])
                                read = read.replace("public/image/eagle.jpg", user["pic"])
                                # print(read)
                                indexLength = len(read.encode())

            responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: text/html; charset=utf-8" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n"+"X-Content-Type-Options: nosniff""\r\n\r\n" + read
            responseString = responseString.strip()
            # print(responseString)
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
            # print(request.path)
            #######send 404
            split = request.path.split("/")[3]
            if "/" not in split:
                # print(split)
                # pictures[i] = "/public/image/" + pictures[i]
                # if "/" not in request.path:
                index = open(request.path[1:], "rb").read()
                indexLength = len(index)
                responseString = "" + request.http_version + " 200 OK" + "\r\n" + "Content-Type: image/jpeg" + "\r\n" + "Content-Length: " + str(indexLength) + "\r\n" + "X-Content-Type-Options: nosniff" + "\r\n\r\n"
                # print(responseString)
                responseString = responseString.encode()
                responseString += index
                # print(responseString)
                self.request.sendall(responseString)

        elif request.path == "/favicon.ico":
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
                # print(request.headers)
                cookieheader = request.headers.get("Cookie")
                # print(cookieheader)
                if cookieheader != None:
                    cookieheader = cookieheader.split(";")
                    # print(cookieheader)
                    for cookie in cookieheader:
                        cookie = cookie.split("=")
                        # print("cookiies: "+ str(cookie))
                        if cookie[0] == "Auth" or cookie[0] == " Auth":
                            # bcrypt.checkpw(password.encode(), user_collection.find_one({"username": username})["password"]):
                            user = user_collection.find_one({"Auth": cookie[1]})
                            # print("got user using cookie:"+ str(user))
                            chat_collection.insert_one({"username": user["username"], "message": message})
                            hol = True
                if hol == False:
                    # print("guest")
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
            user_collection.insert_one({"username": username,"password":hashedPassword,"Auth": None, "pic": "public/image/eagle.jpg"})

        elif request.path == "/websocket":
            key = request.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

            sha1 = hashlib.sha1()
            sha1.update(key.encode())
            key = sha1.digest()
            baseKey = base64.b64encode(key).decode()
            username = ""
            hol = False
            cookieheader = request.headers.get("Cookie")
            if cookieheader != None:
                cookieheader = cookieheader.split(";")
                for cookie in cookieheader:
                    cookie = cookie.split("=")
                    if cookie[0] == "Auth" or cookie[0] == " Auth":
                        user = user_collection.find_one({"Auth": cookie[1]})
                        username = user["username"]
                        # print(username)
                        # print(user["Auth"])
                        hol = True
            if hol == False:
                username = "guest"

            responseString = "" + request.http_version + " 101 Switching Protocols" + "\r\n" +"Upgrade: websocket"+"\r\n" +"Connection: Upgrade"+"\r\n"+"Sec-WebSocket-Accept: " + baseKey+"\r\n"+ "Content-Type: text/html; charset=utf-8" + "\r\n" + "Content-Length: " + str(0) + "\r\n" + "X-Content-Type-Options: nosniff" + "\r\n\r\n"
            # print(responseString)
            self.request.sendall(responseString.encode())
            MyTCPHandler.websocket_connections.append(self.request)
            buffer = bytearray()
            while True:
                #maybe switch to finbit if this doenst work
                received_data = self.request.recv(2048)
                if not received_data:
                    break
                buffer.extend(received_data)
                while True:
                    sendArr = bytearray()
                    if len(buffer) < 2:
                        break

                    #Start reading for frame info
                    opcode = buffer[0] & 15  # 0000 1111the first 4 bits are zeroed and the last 4 are opcode
                    if opcode == 8:
                        MyTCPHandler.websocket_connections.remove(self.request)
                        break
                    #####FinBit
                    finBit = buffer[0] & 128  #1000 0000 gets the first bit
                    if finBit == 128:
                        finBit = 1
                    else:
                        finBit = 0
                    ####MaskBit
                    maskBit = buffer[1] & 128
                    if maskBit == 128:
                        maskBit = 1
                    else:
                        maskBit = 0

                    payloadLen = buffer[1] & 127 # 0111 1111
                    paysize = 0
                    if payloadLen == 126:
                        paysize = 2
                        print("medium message")
                        payloadLen = int.from_bytes(buffer[3:5], byteorder='big')#gets the length from the 3 byte and 4 byte
                    elif payloadLen == 127:
                        paysize = 8
                        print("large messaage")
                        payloadLen = int.from_bytes(buffer[3:11], byteorder='big') #gets the length from the 3 byte to10byte
                    else:
                        paysize = 0
                        print("small message")
                    payloadLenCopy = payloadLen
                    payload = bytearray()
                    if maskBit ==1:
                        maskingKey = received_data[2 + paysize : 6 + paysize]
                        i = 6
                        while payloadLenCopy >= 4:
                            payload.append(received_data[i] ^ maskingKey[0])
                            payload.append(received_data[i + 1] ^ maskingKey[1])
                            payload.append(received_data[i + 2] ^ maskingKey[2])
                            payload.append(received_data[i + 3] ^ maskingKey[3])
                            i += 4
                            payloadLenCopy -= 4
                        m = 0
                        while payloadLenCopy != 0:
                            payload.append(received_data[i] ^ maskingKey[m])
                            i += 1
                            m += 1
                            payloadLenCopy -= 1
                    else:
                        i = 2 + paysize
                        while payloadLenCopy >= 4:
                            payload.append(received_data[i])
                            payload.append(received_data[i + 1])
                            payload.append(received_data[i + 2])
                            payload.append(received_data[i + 3])
                            i += 4
                            payloadLenCopy -= 4
                        m = 0
                        while payloadLenCopy != 0:
                            payload.append(received_data[i])
                            i += 1
                            m += 1
                            payloadLenCopy -= 1
                    ###payload accumlated
                    print(payload)
                    payload = payload.decode()
                    payload = json.loads(payload)
                    # print(payload)
                    message = payload["message"]
                    type = payload["messageType"]
                    id = username + secrets.token_hex(10)
                    # escape user comments
                    message = message.replace("&", "&amp;")
                    message = message.replace("<", "&lt;")
                    message = message.replace(">", "&gt;")
                    ###
                    payload["message"] = message
                    payload["id"] = id
                    payload["username"] = username
                    payloadJson = json.dumps(payload)
                    print(payloadJson)
                    payloadJson = payloadJson.encode()
                    sendPayloadLen = len(payloadJson)
                    sendArr = bytearray()
                    byte1 = finBit * 128 + opcode
                    chat_collection.insert_one({"username": username, "message": message, "messageType": 'chatMessage'})
                    sendArr.append(byte1)
                    byte2 = 0
                    if sendPayloadLen < 126:
                        byte2 = sendPayloadLen
                        sendArr.append(byte2)
                    elif sendPayloadLen >= 126 and sendPayloadLen < 65536:
                        print("medium")
                        byte2 = 128 | 126
                        sendArr.append(byte2)
                        sendArr.extend(sendPayloadLen.to_bytes(2, byteorder='big'))
                    elif sendPayloadLen >= 65536:
                        print("large")
                        byte2 = 128 | 127
                        sendArr.extend(sendPayloadLen.to_bytes(8, byteorder='big'))
                        #maybe its not covering all 2 bytes for the length so its messing up the format
                        sendArr.append(sendPayloadLen)
                    pa = bytearray(payloadJson)
                    sendArr = sendArr + pa
                    print(sendArr)
                for connect in MyTCPHandler.websocket_connections:
                    connect.sendall(sendArr)


        elif request.path == "/login":
            #get the username and the password from the encoded url whcih will be in the body of the request
            body = request.body.decode()
            #inputted hello and hi for username and password
            # username_reg=hello&password_reg=hi
            # print(request.headers[
            # "Content-Length"])
            length = request.headers["Content-Length"]
            username = body.split("&")[0].split("=")[1]
            # print(username)
            password = body.split("&")[1].split("=")[1]
            # print(password)
            if user_collection.find_one({"username": username}) == None:
                print("user not foound")
            # print(user_collection.find_one({"username": username})["password"])
            elif bcrypt.checkpw(password.encode(),user_collection.find_one({"username": username})["password"]):
                print("logged in")
                authtoken = secrets.token_bytes()
                # print("token: " + str(authtoken))
                # sha256 = hashlib.sha256(authtoken).digest()
                # authTokenHash = sha256.update(authtoken)
                authTokenHash = hashlib.sha256(authtoken).hexdigest()
                # print("hashed: "  +str(authTokenHash))
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

        elif request.path == "/profile-pic":
            cookieheader = request.headers.get("Cookie")
            while request.len < int(request.neededLen):
                received_data = self.request.recv(2048)
                print(received_data)
                request2 = Buffer(received_data)
                request.len += len(request2.buffy)
                request.body = request.body + request2.buffy
            print("profiel pic")
            if cookieheader != None:
                cookieheader = cookieheader.split(";")
                # print(cookieheader)
                for cookie in cookieheader:
                    cookie = cookie.split("=")
                    # print("cookiies: " + str(cookie))
                    if cookie[0] == "Auth" or cookie[0] == " Auth":
                        print("user logged in")
                        ##save the file into the disk
                        # user_collection
                        userCookie = cookie[1]
                        for user in user_collection.find({}):
                            if user["Auth"] == userCookie:
                                username = user["username"]
                                print(user["username"])
                                # using W with open creates a file
                                fileName = "public/image/"+username + ".jpg"
                                with open(fileName, "wb") as f:
                                    data = request.body
                                    # print(data)
                                    f.write(data)
                                    user_collection.update_one({"username": username}, {"$set": {"pic": fileName}})

            else:
                print("not logged in")
                print(request.http_version)
            responseString = "" + str(request.http_version) + " 302 FOUND" + "\r\n"+"Location: /" + "\r\n"+ "Content-Type: text/html; charset=utf-8" + "\r\n" + "Content-Length: 0" + "\r\n" + "X-Content-Type-Options: nosniff" +"\r\n\r\n"
            responseString = responseString.encode()
            self.request.sendall(responseString)

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
    # port = 8000
    port = 8080

    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)


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