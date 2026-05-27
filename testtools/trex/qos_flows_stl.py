import argparse
import struct

from trex_stl_lib.api import *


def parse_qos_flows(spec):
    flows = []
    for idx, part in enumerate(spec.split(",")):
        fields = part.strip().split(":")
        if len(fields) == 2:
            qfi, qos_class = fields
        elif len(fields) == 3:
            _, qfi, qos_class = fields
        else:
            raise argparse.ArgumentTypeError(
                "qos flow must be QFI:class or QERID:QFI:class"
            )
        qfi = int(qfi)
        qos_class = int(qos_class)
        if qfi <= 0 or qfi > 63:
            raise argparse.ArgumentTypeError("QFI must be 1..63")
        if qos_class not in (1, 2, 3):
            raise argparse.ArgumentTypeError("class must be 1, 2, or 3")
        flows.append({"qfi": qfi, "class": qos_class, "idx": idx})
    return flows


def build_gtpu_gpdu(teid, qfi, inner_payload):
    # Flags 0x34: GTPv1, PT=1, extension-header flag set.
    # Optional fields carry next extension type 0x85 (PDU Session Container).
    ext = bytes([1, 0, qfi & 0x3F, 0])
    length = 4 + len(ext) + len(inner_payload)
    return (
        struct.pack("!BBHIHBB", 0x34, 0xFF, length, teid, 0, 0, 0x85)
        + ext
        + inner_payload
    )


def pad(pkt, frame_size):
    if len(pkt) >= frame_size:
        return pkt
    return pkt / Raw(b"\x00" * (frame_size - len(pkt)))


class UPFQoSFlowProfile:
    def get_streams(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(
            description="UPF intra-slice QoS-flow steering profile"
        )
        parser.add_argument("--direction", choices=["ul", "dl", "mixed"], default="ul")
        parser.add_argument("--qos-flows", type=parse_qos_flows, default=parse_qos_flows("7:1,8:2,9:3"))
        parser.add_argument("--latency-qfi", type=int, default=7)
        parser.add_argument("--latency-pps", type=int, default=1000)
        parser.add_argument("--background-pps", type=int, default=50000)
        parser.add_argument("--frame-size", type=int, default=128)
        parser.add_argument("--teid", type=int, default=1)
        parser.add_argument("--gnb-ip", default="172.16.1.1")
        parser.add_argument("--upf-n3-ip", default="127.0.0.8")
        parser.add_argument("--ue-ip", default="60.60.0.6")
        parser.add_argument("--remote-ip", default="1.1.1.1")
        parser.add_argument("--remote-port-base", type=int, default=5000)
        parser.add_argument("--ue-port-base", type=int, default=6000)
        args = parser.parse_args(tunables)

        streams = []
        for flow in args.qos_flows:
            qfi = flow["qfi"]
            idx = flow["idx"]
            remote_port = args.remote_port_base + idx
            ue_port = args.ue_port_base + idx
            pps = args.latency_pps if qfi == args.latency_qfi else args.background_pps

            if args.direction in ("ul", "mixed"):
                flow_stats = STLFlowLatencyStats(pg_id=idx + 1) if qfi == args.latency_qfi else None
                inner = (
                    IP(src=args.ue_ip, dst=args.remote_ip)
                    / UDP(sport=ue_port, dport=remote_port)
                    / Raw(b"U" * 16)
                )
                gtpu = build_gtpu_gpdu(args.teid, qfi, bytes(inner))
                ul_pkt = (
                    Ether()
                    / IP(src=args.gnb_ip, dst=args.upf_n3_ip)
                    / UDP(sport=2152 + idx, dport=2152)
                    / Raw(gtpu)
                )
                streams.append(
                    STLStream(
                        name="ul_qfi_%d_class_%d" % (qfi, flow["class"]),
                        packet=STLPktBuilder(pkt=pad(ul_pkt, args.frame_size)),
                        mode=STLTXCont(pps=pps),
                        flow_stats=flow_stats,
                    )
                )

            if args.direction in ("dl", "mixed"):
                flow_stats = STLFlowLatencyStats(pg_id=1000 + idx + 1) if qfi == args.latency_qfi else None
                dl_pkt = (
                    Ether()
                    / IP(src=args.remote_ip, dst=args.ue_ip)
                    / UDP(sport=remote_port, dport=ue_port)
                    / Raw(b"D" * 16)
                )
                streams.append(
                    STLStream(
                        name="dl_qfi_%d_class_%d" % (qfi, flow["class"]),
                        packet=STLPktBuilder(pkt=pad(dl_pkt, args.frame_size)),
                        mode=STLTXCont(pps=pps),
                        flow_stats=flow_stats,
                    )
                )

        return streams


def register():
    return UPFQoSFlowProfile()
