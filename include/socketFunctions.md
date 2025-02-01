# Functions

---

## 1. blacklistedThreadFunction
### Synopsis
	/include/socketFunctions.h

	void* blacklistedThreadFunction(void* args);

### Description
	Receives data from client and sends a response. The response defaults to "default.<file type>" but can be changed.

---

## 1. getHTTPRequestType
### Synopsis
	/include/socketFunctions.h

	int getHTTPRequestType(const unsigned char* receivedData);

### Description
	Parses an HTTP request string and returns the request type. See **Return Value** for details.

### Return Value
	0: error
	1: GET request
	2: POST request
	3: HEAD request
	4: DELETE request
	5: PATCH request
	6: TRACE request
	7: CONNECT request

---

## 1. getRequestedObject
### Synopsis
	/include/socketFunctions.h

	void getRequestedObject(const unsigned char *requestMessage, char *requestedObject)

### Description
	From HTTP request message in *requestMessage* extract the requested object.

### Return Value
	If requested object is "/", returns "index.html". Else, return requested object.

---

# Structures
