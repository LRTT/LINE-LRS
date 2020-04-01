import requests
import rsa
import time
import json

class DeviceInfo:
    applicationType = "DESKTOPWIN"
    applicationVersion = "5.22.0.2111"
    systemName = "WINDOWS"
    systemVersion = "10.0.0-NT-x64"
    name = "DESKTOPWIN_5.22.0.2111_DESKTOP-RN3GPEP"
    model = "DESKTOPWIN_5.22.0.2111_DESKTOP-RN3GPEP#"

class LineLRS:
    BASE_HOST = "w.line.me"
    RELEASE = "/lrs"
    REGISTRATION_HEADER = {
        "Accept": "application/json;charset=UTF-8",
        "Content-Type": "application/json;charset=UTF-8",
        "X-Line-Application": "%s\t%s\t%s\t%s" % (DeviceInfo.applicationType, DeviceInfo.applicationVersion, DeviceInfo.systemName, DeviceInfo.systemVersion)
    }

    def __init__(self, region, phone, password, debug=False):
        self.region = region
        self.phone = phone
        self.password = password
        self.debug = debug
        self.session = requests.Session()

    def request(self, headers, data):
        date = "?t=%s" % (int(int(time.time())*1000))
        if data["type"] == "POST":
            response = self.session.post("https://" + self.BASE_HOST + self.RELEASE + data["path"] + date, data=None if "data" not in data else json.dumps(data["data"]), headers=headers).json()
        elif data["type"] == "GET":
            response = self.session.get("https://" + self.BASE_HOST + self.RELEASE + data["path"] + date, headers=headers).json()
        elif data["type"] == "PUT":
            response = self.session.post("https://" + self.BASE_HOST + self.RELEASE + data["path"] + date, data=None if "data" not in data else json.dumps(data["data"]), headers=headers).json()
        else:
            raise Exception("invaild data type")
        if self.debug:
            print("https://" + self.BASE_HOST + self.RELEASE + data["path"] + date)
            print(response)
        if "error" in response:
            raise Exception(response["message"])
        if "result" in response:
            return response["result"]

    def getCountries(self, countryGroup):
        #TYPE: "POST",
        #PATH: "/v1/countries"
        data = { "countryGroup": countryGroup }
        return self.request(self.REGISTRATION_HEADER, { "type": "POST", "path": "/v1/countries", "data": data })

    def startVerification(self):
        # TYPE: "POST",
        # PATH: "/v1/reg"
        data = {
            "region": self.region,
            "phoneNumber": self.phone,
            "deviceInfo": {
                "applicationType": DeviceInfo.applicationType,
                "deviceName": DeviceInfo.name,
                "systemName": DeviceInfo.systemName,
                "systemVersion": DeviceInfo.systemVersion,
                "model": DeviceInfo.model
            },
            "locale": "th"
        }
        return self.request(self.REGISTRATION_HEADER, { "type": "POST", "path": "/v1/reg", "data": data })

    def resendVerificationNumber(self):
        # TYPE: "GET",
        # PATH: "/v1/reg/{sessionId}/resend"
        pass

    def changeVerificationMethod(self):
        # TYPE: "POST",
        # PATH: "/v1/reg/{sessionId}/change"
        pass

    def verifyPhoneNumber(self, sessionId, pincode):
        # TYPE: "POST",
        # PATH: "/v1/reg/{sessionId}/verify"
        data = { "pincode": pincode }
        return self.request(self.REGISTRATION_HEADER, { "type": "POST", "path": "/v1/reg/%s/verify" % (sessionId), "data": data })

    def getRSAKey(self):
        # TYPE: "GET",
        # PATH: "/v1/reg/rsaKey"
        return self.request(self.REGISTRATION_HEADER, { "type": "GET", "path": "/v1/reg/rsaKey?_=%s" % (int(time.time())) })

    def registerPassword(self):
        # TYPE: "POST",
        # PATH: "/v1/reg/{sessionId}/password"
        pass

    def create(self, sessionId, payload):
        # TYPE: "POST",
        # PATH: "/v1/reg/{sessionId}/create"
        data = {
            "keynm": payload["keynm"],
            "encryptedPassword": payload["encryptedPassword"]
        }
        response = self.request(self.REGISTRATION_HEADER, { "type": "POST", "path": "/v1/reg/%s/create" % (sessionId), "data": data })
        self.REGISTRATION_HEADER["X-Line-Access"] = response["authToken"]
        return response

    def startEmailConfirmation(self, payload):
        # TYPE: "POST",
        # PATH: "/v1/post/reg/email/start"
        data = {
            "keynm": payload["keynm"],
            "encryptedIdPassword": payload["encryptedIdPassword"],
            "ignoreDuplication": payload["ignoreDuplication"]
        }
        return self.request(self.REGISTRATION_HEADER, { "type": "POST", "path": "/v1/post/reg/email/start", "data": data })

    def resendEmail(self):
        # TYPE: "POST",
        # PATH: "/v1/post/reg/email/resend"
        pass

    def resetEmail(self):
        # TYPE: "POST",
        # PATH: "/v1/post/reg/email/reset"
        pass

    def confirmEmail(self, verifier, pincode):
        # TYPE: "POST",
        # PATH: "/v1/post/reg/email/confirm"
        data = {
            "verifier": verifier,
            "pincode": pincode
        }
        return self.request(self.REGISTRATION_HEADER, { "type": "POST", "path": "/v1/post/reg/email/confirm", "data": data })

    def getProfile(self):
        # TYPE: "GET",
        # PATH: "/v1/post/reg/profile"
        return self.request(self.REGISTRATION_HEADER, { "type": "GET", "path": "/v1/post/reg/profile" })

    def updateProfileAttributes(self, payload):
        # TYPE: "PUT",
        # PATH: "/v1/post/reg/profile/attr"
        return self.request(self.REGISTRATION_HEADER, { "type": "PUT", "path": "/v1/post/reg/profile/attr", "data": payload })

    def updateProfile(self, payload):
        # TYPE: "PUT",
        # PATH: "/v1/post/reg/profile"
        return self.request(self.REGISTRATION_HEADER, { "type": "PUT", "path": "/v1/post/reg/profile", "data": payload })

    def getSettings(self):
        # TYPE: "GET",
        # PATH: "/v1/post/reg/settings"
        return self.request(self.REGISTRATION_HEADER, { "type": "GET", "path": "/v1/post/reg/settings" })

    def getSettingsAttribute(self, payload):
        # TYPE: "POST",
        # PATH: "/v1/post/reg/settings/attr"
        return self.request(self.REGISTRATION_HEADER, { "type": "POST", "path": "/v1/post/reg/settings/attr", "data": payload })

    def updateSettingsAttribute(self, payload):
        # TYPE: "PUT",
        # PATH: "/v1/post/reg/settings/attr"
        return self.request(self.REGISTRATION_HEADER, { "type": "PUT", "path": "/v1/post/reg/settings/attr", "data": payload })

def getPlain(*args):
    return (''.join([(chr(len(data)) + data) for data in args])).encode('utf-8')

def rsaEncrypt(plain, nvalue, evalue):
    key = rsa.PublicKey(int(nvalue, 16), int(evalue, 16))
    return rsa.encrypt(plain, key).hex()

def registerSecondaryWithPhone(country, phone, password, name=None, debug=False):
    debugger = lambda string: print(string) if debug else None
    client = LineLRS(country, phone, password)
    startVerificationResponse = client.startVerification()
    normalizedPhone = startVerificationResponse["normalizedPhone"]
    sessionId = startVerificationResponse["sessionId"]
    pincode = input("SMS Pin Code: ")
    verifyPhoneNumberResponse = client.verifyPhoneNumber(sessionId, pincode)
    if verifyPhoneNumberResponse["verificationResult"] == "FAILED":
        raise Exception("verification failed")
    getRSAKeyResponse = client.getRSAKey()
    plainText = getPlain(getRSAKeyResponse["sessionKey"], normalizedPhone.replace(" ", ""), client.password)
    encryptedPassword = rsaEncrypt(plainText, getRSAKeyResponse["nvalue"], getRSAKeyResponse["evalue"])
    createPayload = {
        "keynm": getRSAKeyResponse["keynm"],
        "encryptedPassword": encryptedPassword
    }
    createResponse = client.create(sessionId, createPayload)
    debugger("Auth Token: %s" % (createResponse["authToken"]))
    debugger("Register Certificate: %s" % (createResponse["certificate"]))
    profileResponse = client.getProfile()
    debugger("Mid: %s" % (profileResponse["mid"]))
    debugger("Display Name: %s" % (profileResponse["displayName"]))
    result = {"authToken": createResponse["authToken"], "registerCertificate": createResponse["certificate"]}
    if mail:
        getRSAKeyResponse = client.getRSAKey()
        plainText = getPlain(getRSAKeyResponse["sessionKey"], mail, normalizedPhone.replace(" ", ""))
        encryptedIdPassword = rsaEncrypt(plainText, getRSAKeyResponse["nvalue"], getRSAKeyResponse["evalue"])
        startEmailConfirmationPayload = {
            "keynm": getRSAKeyResponse["keynm"],
            "encryptedIdPassword": encryptedIdPassword,
            "ignoreDuplication": 1
        }
        startEmailConfirmationResponse = client.startEmailConfirmation(startEmailConfirmationPayload)
        pincode = input("Mail Pin Code: ")
        confirmEmailResponse = client.confirmEmail(startEmailConfirmationResponse["verifier"], pincode)
        debugger("Mail: %s" % (mail))
        debugger("Mail Certificate: %s" % (confirmEmailResponse["certificate"]))
        result["mail"] = mail
        result["mailCertificate"] = confirmEmailResponse["certificate"]
    return result

if __name__ == "__main__":
    registerSecondaryWithPhone("ID", "0805864712", "pasunx1234aaa")