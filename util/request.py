def pic(request):
    # print(request)
    newLine = "\r\n\r\n".encode()

    requestSplit = request.split(newLine)
    # print(requestSplit[0])
    requestSplitHead = requestSplit[0].decode()
    i = 0
    meth = ""
    while requestSplitHead[i] != " ":
        meth += requestSplitHead[i]
        i += 1
    i += 1
    path = ""
    while requestSplitHead[i] != " ":
        path += requestSplitHead[i]
        i += 1
    http = requestSplit[0].split()[2]
    headers = {}
    # heads = requestSplitHead.split("\r\n-")
    # #Content-Type: multipart/form-data; boundary=---------------------------384805787219015053722903573873 when user is goes to profile-pic
    # bou = "-"+heads[1]
    # new = bou.split("\r\n")
    # heads = heads[0].split("\r\n")
    spli = requestSplitHead.split("boundary=")
    heads = spli[0].split("\r\n")
    for item in heads[1:]:
        headers[item.split(": ")[0]] = item.split(": ")[1]
    heads = spli[1].split("\r\n")
    bound = heads[0]
    for item in heads[1:]:
        headers[item.split(": ")[0]] = item.split(": ")[1]
    # requestSplit[1] = requestSplit[1].split(("\r\n"+bound+"--"+"\r\n").encode())
    # print(requestSplit[2])
    file = requestSplit[2].split("-".encode())

    # print({"method":meth,"path":path,"headers":headers,"body":file[0]})
    return {"method":meth,"path":path,"headers":headers,"body":file[0],"http":http}

class Request:

    def __init__(self, request: bytes):
        # TODO: parse the bytes of the request and populate the following instance variables
        if request == b'':
            self.path = "err"
            return
        if request[0:17] == b'POST /profile-pic':
            res = pic(request)
            self.method = res["method"]
            self.path = res["path"]
            self.headers = res["headers"]
            self.body = res["body"]
            self.http_version = res["http"]

        else:
            decoded = request.decode()
            decoded.strip()
            # print("preprocc" + str(decoded))
            self.body = b""
            i = 0
            meth = ""
            while decoded[i] != " ":
                meth += decoded[i]
                i += 1
            self.method = "" + meth
            i += 1
            path = ""
            while decoded[i] != " ":
                path += decoded[i]
                i += 1
            self.path = "" + path
            # if path != "/chat-history":
                # print(decoded)
            spaceSplit = decoded.split()
            version = spaceSplit[2]
            self.http_version = "" + version
            decoded = decoded.splitlines()
            # print("split: "+str(decoded))
            decoded = list(filter(None,decoded))
            # print("filtered: "+ str(decoded))
            if self.method != "GET" and self.method != "DELETE":
                self.body = b"" + decoded[len(decoded)-1].encode()
            bd = self.body
            # print(bd)
            if(self.method == "DELETE"):
                decoded = decoded[1:]
            else:
                decoded = decoded[1:-1]
            self.headers = {}
            for item in decoded:
                items = item.split(": ")
                self.headers[items[0]] = items[1]


