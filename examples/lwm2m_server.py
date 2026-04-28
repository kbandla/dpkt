#!/usr/bin/env python
"""
LWM2M Server Example
Listens for Registration and sends a Read request.
"""
import os
import socket
import dpkt

def run_server():
    # Configuration
    BIND_HOST = os.environ.get('LWM2M_BIND_HOST', '127.0.0.1')
    SERVER_PORT = 5683

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_HOST, SERVER_PORT))
    sock.settimeout(10.0)

    print(f"[*] LWM2M Server started on port {SERVER_PORT}")

    try:
        # 1. Wait for Registration
        print("[*] Waiting for Registration...")
        data, addr = sock.recvfrom(1024)
        reg = dpkt.coap.CoAP(data)
        
        # Extract Endpoint (ep) from URI-Query
        endpoint = "unknown"
        for opt_num, opt_val in reg.opts:
            if opt_num == dpkt.coap.COAP_OPT_URI_QUERY:
                if b"ep=" in opt_val:
                    endpoint = opt_val.decode().split('=')[1]
        
        print(f"[*] Received Registration from {addr}: '{endpoint}'")
        if reg.data:
            print(f"    [+] Supported Objects: {reg.data.decode()}")

        # 2. Send Read Request: GET /3/0/0 (Device Manufacturer)
        read_req = dpkt.coap.CoAP(
            t=dpkt.coap.COAP_CON,
            code=dpkt.coap.COAP_GET,
            id=42,
            token=b'\x01\x02\x03\x04'
        )
        # Adding URI-Path: "3", "0", "0"
        read_req.opts.append((dpkt.coap.COAP_OPT_URI_PATH, b'3'))
        read_req.opts.append((dpkt.coap.COAP_OPT_URI_PATH, b'0'))
        read_req.opts.append((dpkt.coap.COAP_OPT_URI_PATH, b'0'))
        
        print(f"[*] Sending Read request for /3/0/0 to {endpoint}...")
        sock.sendto(bytes(read_req), addr)

        # 3. Receive Read Response
        data, addr = sock.recvfrom(1024)
        resp = dpkt.coap.CoAP(data)
        
        print(f"[*] Received Read Response: Code={resp.code}")
        
        # 4. Parse LWM2M TLV data via the format-agnostic decoder.
        from dpkt.lwm2m import LWM2M
        decoded = LWM2M.decode(resp.data, LWM2M.ContentFormat.TLV)
        # decode() returns a single Resource for a one-resource payload,
        # or an ObjectInstance / list for richer responses.
        resources = (decoded.resources if isinstance(decoded, LWM2M.ObjectInstance)
                     else [decoded] if isinstance(decoded, LWM2M.Resource)
                     else decoded)
        for r in resources:
            if r.id == dpkt.lwm2m.LWM2M_DEV_MANUFACTURER:
                print(f"    [+] Resource ID {r.id} (Manufacturer): {r.value.decode()}")
            else:
                print(f"    [+] Resource ID {r.id}: {r.value}")

    except socket.timeout:
        print("[!] Timeout: No messages received.")
    finally:
        sock.close()

if __name__ == "__main__":
    run_server()
