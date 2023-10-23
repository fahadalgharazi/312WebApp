class Request:

    def __init__(self, request: bytes):
        # TODO: parse the bytes of the request and populate the following instance variables
        if request == b'':
            self.path = "err"
            return
        decoded = request.decode()
        decoded.strip()
        print("preprocc" + str(decoded))
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
        spaceSplit = decoded.split()
        version = spaceSplit[2]
        self.http_version = "" + version
        decoded = decoded.splitlines()
        print("split: "+str(decoded))
        decoded = list(filter(None,decoded))
        print("filtered: "+ str(decoded))

        self.body = b"" + decoded[len(decoded)-1].encode()
        if(self.method == "DELETE"):
            decoded = decoded[1:]
        else:
            decoded = decoded[1:-1]
        print(decoded)
        self.headers = {}
        for item in decoded:
            items = item.split(": ")
            self.headers[items[0]] = items[1]
