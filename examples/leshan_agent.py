#!/usr/bin/env python
import os
import socket
import dpkt
import struct
import time
import select
from dpkt.lwm2m import LWM2M

def default_bind_host(server_host, server_port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((server_host, server_port))
        return probe.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        probe.close()

def run_leshan_agent():
    SERVER_HOST = os.environ.get('LESHAN_HOST', 'leshan.eclipseprojects.io')
    SERVER_PORT = 5683
    BIND_HOST = os.environ.get('LWM2M_BIND_HOST', default_bind_host(SERVER_HOST, SERVER_PORT))
    ENDPOINT = 'dpkt-agent-2026'
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_HOST, 5685))
    sock.setblocking(0)

    def send_reg(is_update=False):
        # Register Object 3 (Device), 6 (Location), and 3303 (Temperature)
        reg = dpkt.coap.CoAP(
            t=dpkt.coap.COAP_CON,
            code=dpkt.coap.COAP_POST,
            id=int(time.time()) & 0xFFFF,
            token=b'\xaa\xbb',
            data=b'</3/0>,</6/0>,</3303/0>' if not is_update else b''
        )
        reg.opts.append((dpkt.coap.COAP_OPT_URI_PATH, b'rd'))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, f"ep={ENDPOINT}".encode()))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, b"lwm2m=1.0"))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, b"lt=86400"))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, b"b=U"))
        reg.opts.append((dpkt.coap.COAP_OPT_CONTENT_FORMAT, struct.pack('B', dpkt.coap.COAP_FORMAT_LINK)))
        sock.sendto(bytes(reg), (SERVER_HOST, SERVER_PORT))
        print(f"[*] Sent {'Update' if is_update else 'Registration'} for {ENDPOINT}")

    send_reg()
    last_update = time.time()
    
    try:
        while True:
            ready = select.select([sock], [], [], 1.0)
            if ready[0]:
                data, addr = sock.recvfrom(2048)
                try:
                    req = dpkt.coap.CoAP(data)
                    paths = []
                    accept = None
                    for opt_num, opt_val in req.opts:
                        if opt_num == dpkt.coap.COAP_OPT_URI_PATH:
                            paths.append(opt_val.decode())
                        if opt_num == dpkt.coap.COAP_OPT_ACCEPT:
                            if not opt_val: accept = 0
                            elif len(opt_val) == 1: accept = struct.unpack('B', opt_val)[0]
                            elif len(opt_val) == 2: accept = struct.unpack('>H', opt_val)[0]

                    path_str = "/" + "/".join(paths)
                    
                    if req.code == dpkt.coap.COAP_GET:
                        print(f"[*] Received CoAP GET {path_str} (Accept={accept})")

                        # Route by Object ID — build resources as native Python
                        # values; LWM2M.encode handles TLV/JSON serialization.
                        obj_id = int(paths[0])
                        if obj_id == 3:  # Device
                            resources = [
                                LWM2M.Resource(0,  'dpkt-project'),
                                LWM2M.Resource(1,  'cli-agent-v1.2'),
                                LWM2M.Resource(2,  'SN-2026-DPKT'),
                                LWM2M.Resource(3,  '1.9.8'),
                                LWM2M.Resource(6,  instances={0: 1}),
                                LWM2M.Resource(7,  instances={0: 3800}),
                                LWM2M.Resource(9,  95),
                                LWM2M.Resource(10, 1024),
                                LWM2M.Resource(13, int(time.time())),
                                LWM2M.Resource(14, '+01:00'),
                                LWM2M.Resource(15, 'Europe/Stockholm'),
                                LWM2M.Resource(17, 'DPKT-Map-Agent'),
                                LWM2M.Resource(18, 'v1.0-virtual'),
                                LWM2M.Resource(20, 1),
                                LWM2M.Resource(21, 2048),
                            ]
                        elif obj_id == 6:  # Location (Stockholm)
                            resources = [
                                LWM2M.Resource(0, 59.3293),
                                LWM2M.Resource(1, 18.0686),
                                LWM2M.Resource(2, 15.0),
                                LWM2M.Resource(5, int(time.time())),
                            ]
                        elif obj_id == 3303:  # Temperature
                            resources = [
                                LWM2M.Resource(5700, 21.5),
                                LWM2M.Resource(5701, 'Cel'),
                            ]
                        else:
                            resources = []

                        if not resources:
                            resp = dpkt.coap.CoAP(t=dpkt.coap.COAP_ACK, code=dpkt.coap.COAP_NOT_FOUND, id=req.id, token=req.token)
                            sock.sendto(bytes(resp), addr)
                            continue

                        # Decide what to return: a single Resource (deep path)
                        # or the whole ObjectInstance (shorter path).
                        if len(paths) >= 3:
                            res_id = int(paths[-1])
                            target = next((r for r in resources if r.id == res_id), None)
                            if target is None:
                                resp = dpkt.coap.CoAP(t=dpkt.coap.COAP_ACK, code=dpkt.coap.COAP_NOT_FOUND, id=req.id, token=req.token)
                                sock.sendto(bytes(resp), addr)
                                continue
                        else:
                            inst_id = int(paths[1]) if len(paths) > 1 else 0
                            target = LWM2M.ObjectInstance(id=inst_id, resources=resources)

                        # Pick wire format based on Accept.
                        single_simple = (isinstance(target, LWM2M.Resource)
                                         and not target.is_multi
                                         and isinstance(target.value, (str, int))
                                         and not isinstance(target.value, bool))
                        if accept == dpkt.coap.COAP_FORMAT_LWM2M_JSON:
                            base_path = f'/{obj_id}/{paths[1] if len(paths) > 1 else 0}/'
                            resp_data = LWM2M.encode(target, LWM2M.ContentFormat.JSON, base_path=base_path)
                            content_format = dpkt.coap.COAP_FORMAT_LWM2M_JSON
                        elif (accept in (0, None)) and single_simple:
                            resp_data = str(target.value).encode('utf-8')
                            content_format = dpkt.coap.COAP_FORMAT_TEXT
                        else:
                            resp_data = LWM2M.encode(target, LWM2M.ContentFormat.TLV)
                            content_format = dpkt.coap.COAP_FORMAT_LWM2M_TLV

                        resp = dpkt.coap.CoAP(t=dpkt.coap.COAP_ACK, code=dpkt.coap.COAP_CONTENT, id=req.id, token=req.token, data=resp_data)
                        fmt_val = struct.pack('>H', content_format) if content_format > 255 else struct.pack('B', content_format)
                        resp.opts.append((dpkt.coap.COAP_OPT_CONTENT_FORMAT, fmt_val))
                        sock.sendto(bytes(resp), addr)
                        print(f"    [+] Responded {path_str} (format {content_format})")
                except Exception as e:
                    print(f"[!] Error: {e}")

            if time.time() - last_update > 60:
                send_reg(is_update=True)
                last_update = time.time()

    except KeyboardInterrupt: pass
    finally: sock.close()

if __name__ == "__main__":
    run_leshan_agent()
