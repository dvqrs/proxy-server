def handle_client(client_socket):
    try:
        request = client_socket.recv(4096)
        if not request:
            client_socket.close()
            return

        # Check if this is a simple HTTP GET on "/"
        if request.startswith(b'GET / '):
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nProxy is up!"
            client_socket.sendall(response)
            client_socket.close()
            return

        # Existing logic for CONNECT and other HTTP requests...
        if request.startswith(b'CONNECT'):
            # ... [existing CONNECT logic] ...
            # (unchanged code)
            pass
        else:
            # ... [existing HTTP proxy logic] ...
            pass
    except Exception as e:
        print("Error handling client:", e)
    finally:
        client_socket.close()
