# Functions

---

## 1. setupResponse
### Synopsis
_void setupResponse(struct HTTP_response **destination, int options);_

### Description
sets up http default response and saves it to *destination* as *HTTP_response*

### Return value
none

---

## 2. getHTTPRequestType
### Synopsis
_int getHTTPRequestType(const unsigned char* receivedData);_

### Description
Parses an HTTP request string and returns the request type. See **Return Value** for details.

### Return Value
0: error<br>
1: GET request<br>
2: POST request<br>
3: HEAD request<br>
4: DELETE request<br>
5: PATCH request<br>
6: TRACE request<br>
7: CONNECT request

---

## 3. responseToString
### Synopsis
_int responseToString(const struct HTTP_response *response, char* buffer);_

### Description
write *response* to *buffer*. Carriage return and line feed are added appropriately for http messages.

Any value that was in buffer is set to 0.

buffer size is assumed to be *BUFFER_SIZE*

### Return Value
- 0: success

---

## 4. setupConnectionResources
### Synopsis
*void setupConnectionResources(struct connection_resources* connections, int connection_count, FILE* global_output_file_ptr);*

### Description
initialize *struct connection_resources connections* array

### Return Value
none

---

## 5. setupWhitelist
### Synopsis
_void setupWhitelist(struct whitelist_structure* whitelist);_

### Description
setup a *whitelite_structure* that contains IP addresses, ports, and host names to let through the proxy. This is done by reading *whitelist.txt*. 

### Return Value
none

### Notes
if an error occurs in this error, it is taken to be fatal. Possible sources of errors are: malloc, strcmp.

---

## 6. handleHTTPConnection
### Synopsis
_void handleHTTPConnection();_

### Description
creates a thread that will listen for incoming connections. Each incoming connection is handled by their own threads.

### Return Value
none

---

## 7. setDomainNames
### Synopsis
_void setDomainNames();_

### Description
set the domains that will be used to check the requested domain. This is done by reading *domains.txt*. 

### Return Value
none

### Notes
It might be more efficient to use a macro array instead. Probably will removed later.

Also, errors encountered in this function are fatal errors and will cause the program to terminate.

---

## 8. isWhitelisted
### Synopsis
_bool isWhitelisted(const struct whitelist_structure whitelist, const char *destination_name,const char *destination_port, const struct addrinfo address_info);_

### Description
checks if either the hostname, IP address, or port number is whitelisted.

### Return Value
true: whitelisted<br>
false: not whitelisted

---

## 9. returnListeningSocket
### Synopsis
_int returnListeningSocket();_

### Description
creates, binds, and returns a listening socket

### Return Value
listening socket

### Notes
errors in this function are fatal errors and will cause the program to terminate

---

## 10. returnSocketToClient
### Synopsis
_int returnSocketToClient(const int listening_socket);_

### Description
accepts a connection made to *listening_socket* by a client and returns that socket

hangs while waiting for connection

### Return Value
socket to client<br>
-2: error accepting connection. Error number is printed before returning

---

## 11. getDestinationName
### Synopsis
_int getDestinationName(const unsigned char *received_data, char *destination_name_buffer, FILE *output_file_ptr);_

### Description
extracts destination name string from http request. Uses *domainNames* array to check requested domain

### Return Value
- offset of name from start of data on success
- -1: error finding host string

---

## 12. returnDestinationAddressInfo
### Synopsis
_struct addrinfo returnDestinationAddressInfo(const char *destination_name, const char *destination_port, FILE *output_file_ptr);_

### Description
using *destination_name* and *destination_port* returns *addrinfo* structure. 

prints ip address of destination as well

### Return Value
- *addrinfo* structure containing information about destination on success

### Notes
errors in this function are fatal errors and will cause program to terminate. Because this function is called often, it should be changed to return other values on error and the calling functions should be changed to be able to recover from said errors

---

## 13. returnSocketToServer
### Synopsis
_int returnSocketToServer(const struct addrinfo destination_address_information);_

### Description
create a socket to *destination_addresss_information*. Connect to it and return the socket. 

### Return Value
- socket to the server

### Notes
errors in this function are fatal errors and will cause program to terminate. Because this function is called often, it should be changed to return other values on error and the calling functions should be changed to be able to recover from said errors

---

## 14. whitelistedThreadFunction
### Synopsis
_void *whitelistedThreadFunction(void *args);_

### Description
thread function for connections to whitelisted addresses. Acts as a proxy between the server and client. Data exchanged between the server and client are logged.

May terminate connection when timeout occurs. 

*shutdown* variable in *args* may be set to force thread to terminate

### Return Value
none

---

## 15. listeningThreadFunction
### Synopsis
_void *listeningThreadFunction(void *args);_

### Description
thread to listen for and accept connections. Accepted connections are saved to *accepted_socket* in *args*.

can be forced to terminate via the *shutdown* variable in *args*

### Return Value
none

---

## 16. cleanupConnections
### Synopsis
_void cleanupConnections(struct connection_resources *connection_resource, int connection_count);_

### Description
waits until all threads in *connection_resources* terminates then returns

### Return Value
none

---

## 17. getRequestedObject
### Synopsis
_void getRequestedObject(const unsigned char *request_message, char *requested_object);_

### Description
from *request_message* find the requested object. The requested object is saved to _requested_object_.

if *request_message* is not an http request message, *requested_object* is set to an empty string

### Return Value
none

---

## 18. sendResponse
### Synopsis
_int sendResponse(int socket, const int options, const char *file_type, char *write_buffer, const struct HTTP_response *response, FILE *output_file_ptr);_

### Description
depending on the *file_type* requested, send appropriate file as a response.

If *RESPONSE_NO_PAYLOAD* option is set, sends a response containing no payload.

If the file is an html file, *./files/default.html* is compressed in gzip and sent.

Other file types are not supported yet.

### Return Value
- -1: file type is not supported
- -2: error opening gzip compressed file
- 0: reponse sent successfully

### Options
- RESPONSE_NO_PAYLOAD, 0x1<br>
send no payload with the response

---

## 19. blacklistedThreadFunction
### Synopsis
_void *blacklistedThreadFunction(void *args);_

### Description
thread function for connections with non-whitelisted addresses. 

When http GET request messages are received, sends an appropriate response via *sendResponse*

Other types of http requests are not supported yet and ignored

### Return Value
none

### Error handling
when fatal errors occur, the thread terminates itself

---

# Structures
