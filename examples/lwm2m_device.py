#!/usr/bin/env python
"""
LWM2M Device Example
Simulates an LWM2M Client that registers and responds to Read requests.
"""
import os
import socket
import dpkt

def run_device():
    # Configuration
    BIND_HOST = os.environ.get('LWM2M_BIND_HOST', '127.0.0.1')
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 5683
    DEVICE_PORT = 5684
    ENDPOINT = 'dpkt-device'

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_HOST, DEVICE_PORT))
    sock.settimeout(5.0)

    print(f"[*] LWM2M Device '{ENDPOINT}' started on port {DEVICE_PORT}")

    # 1. Build Registration Request
    # POST /rd?ep=dpkt-device
    # Payload: </3> (Indicates Device Object is available)
    reg = dpkt.coap.CoAP(
        t=dpkt.coap.COAP_CON,
        code=dpkt.coap.COAP_POST,
        id=1,
        token=b'\xde\xad',
        data=b'</3>'
    )
    # Adding URI-Path: "rd"
    reg.opts.append((dpkt.coap.COAP_OPT_URI_PATH, b'rd'))
    # Adding URI-Query: "ep=dpkt-device"
    reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, f"ep={ENDPOINT}".encode()))
    # Content-Format: application/link-format (40)
    reg.opts.append((dpkt.coap.COAP_OPT_CONTENT_FORMAT, struct.pack('B', dpkt.coap.COAP_FORMAT_LINK)))

    
    print(f"[*] Sending Registration to {SERVER_HOST}:{SERVER_PORT}...")
    sock.sendto(bytes(reg), (SERVER_HOST, SERVER_PORT))

    try:
        # 2. Wait for Read Request from Server
        data, addr = sock.recvfrom(1024)
        req = dpkt.coap.CoAP(data)
        
        # Check if it's a GET request for Device Manufacturer (/3/0/0)
        # Note: In a real client we'd parse opts properly
        print(f"[*] Received request from {addr}: Code={req.code}")
        
        # 3. Respond with LWM2M TLV data via the format-agnostic data model.
        from dpkt.lwm2m import LWM2M
        manufacturer = LWM2M.Resource(id=dpkt.lwm2m.LWM2M_DEV_MANUFACTURER,
                                      value='dpkt-project')
        payload = LWM2M.encode(manufacturer, LWM2M.ContentFormat.TLV)

        resp = dpkt.coap.CoAP(
            t=dpkt.coap.COAP_ACK,
            code=dpkt.coap.COAP_CONTENT,
            id=req.id,
            token=req.token,
            data=payload
        )
        resp.opts.append((dpkt.coap.COAP_OPT_CONTENT_FORMAT, struct.pack('>H', dpkt.coap.COAP_FORMAT_LWM2M_TLV)))
        
        print(f"[*] Sending Response: Manufacturer='dpkt-project'")
        sock.sendto(bytes(resp), addr)

    except socket.timeout:
        print("[!] No request received from server.")
    finally:
        sock.close()

if __name__ == "__main__":
    import struct
    run_device()
