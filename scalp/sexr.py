#!/usr/bin/env python3
"""
File: sexr.py
Author: Don C. Weber
Modernized for Python 3 by DragonJAR SAS
Purpose: Scalp External XML Reporter parses Scalp XML files and outputs
alert information, statistics, and detected IP addresses
"""
import datetime
import getopt
import glob
import os
import sys

try:
    from lxml import etree
except ImportError:
    import xml.etree.ElementTree as etree

__application__ = "sexr"
__version__ = "1.0"
__release__ = f"{__application__}/{__version__}"
__author__ = "Don C. Weber (Ported to Python 3 by DragonJAR SAS)"
__copyright__ = "Copyright 2008-2024 Don C. Weber / DragonJAR SAS"


def xparse(xml_file, val_dtd=None):
    """Parses an XML file and validates against DTD if val_dtd is provided."""
    try:
        with open(xml_file, "r", encoding="utf-8", errors="replace") as xml_handler:
            tree = etree.parse(xml_handler)
            root = tree.getroot()
            if val_dtd and hasattr(val_dtd, "validate") and not val_dtd.validate(root):
                print(f"{sys.argv[0]}: XML file does not comply with Scalp DTD: {xml_file}")
                return None
            return root
    except Exception as e:
        print(f"{sys.argv[0]}: Error parsing XML file {xml_file}: {e}")
        return None


def iter_node(node, indent, fOUT):
    """Recursively formats node attributes and tags."""
    indent += "   "
    if len(node.attrib):
        fOUT.write(f"{indent}{node.tag}: {node.attrib}\n")
    else:
        fOUT.write(f"{indent}{node.tag}\n")
    if node.text and node.text.strip():
        fOUT.write(f"{indent} - {node.text.strip()}\n")
    for ch in node:
        iter_node(ch, indent, fOUT)


def item_cnt_iter(node, indent, fOUT, scan_mode="count"):
    """Iterates XML nodes counting attacks or source IPs."""
    indent += "   "
    d_impact = {}
    ip_impact = {}

    if node.tag == "impact":
        fOUT.write(f"{indent}Impact {node.get('value')} Items: {len(node)}\n")
        for i_ch in node:
            for ic_ch in i_ch:
                if ic_ch.tag == "line" and scan_mode == "IP":
                    parts = (ic_ch.text or "").split()
                    if parts:
                        ip = parts[0]
                        ip_impact[ip] = ip_impact.get(ip, 0) + 1
                if ic_ch.tag == "reason" and scan_mode == "count":
                    reason = ic_ch.text or "Unknown"
                    d_impact[reason] = d_impact.get(reason, 0) + 1

        if d_impact and scan_mode == "count":
            for key, value in d_impact.items():
                fOUT.write(f"{indent} - '{key}': {value}\n")
        if ip_impact and scan_mode == "IP":
            fOUT.write(f"{indent} - Total Source IP Addresses: {len(ip_impact)}\n")
            for addr in sorted(ip_impact.keys()):
                fOUT.write(f"{indent} - {addr}: {ip_impact[addr]}\n")
        return

    for ch in node:
        item_cnt_iter(ch, indent, fOUT, scan_mode=scan_mode)


def help():
    print("Scalp External XML Reporter (Python 3 Edition)")
    print("Author: Don C. Weber / Modernized by DragonJAR SAS\n")
    print("usage:   ./sexr.py [-h|--help] [-V|--version] [-v xml_dtd] [-d out_directory]")
    print("                   [-t | -f | -a | -s] <xml file or directory>\n")
    print("    -h | --help:     Print this help.")
    print("    -V | --version:  Version information.")
    print("    -v:              The Scalp DTD file. './scalp_xmldtd.dtd' by default.")
    print("    -d:              The directory to write the output files. './' by default. Implies -t")
    print("    -t:              Text output.")
    print("    -f:              Full parse to selected output format (default).")
    print("    -a:              Provides a count of specific attacks detected.")
    print("    -s:              Provides a count of the Source IP addresses associated with attacks.")


def main():
    if len(sys.argv) < 2 or "-h" in sys.argv or "--help" in sys.argv:
        help()
        sys.exit(0)

    if "-V" in sys.argv or "--version" in sys.argv:
        print(f"Scalp External XML Reporter release: {__release__}")
        sys.exit(0)

    dout = os.getcwd() + "/"
    fhandle = sys.stdout
    fout_ext = ""
    scan = "full"
    dnow = datetime.datetime.now(datetime.timezone.utc)
    fnow = f"{dnow.date()}.{dnow.strftime('%H%M%S')}"
    fdtd = "scalp_xmldtd.dtd"
    vdtd = None

    inXML = sys.argv[-1]

    try:
        opts, args = getopt.getopt(sys.argv[1:-1], "hVv:d:tfas", ["help", "version"])
    except getopt.GetoptError:
        print(f"{sys.argv[0]}: command line error")
        help()
        sys.exit(1)

    for opt, arg in opts:
        if opt == "-v":
            fdtd = os.path.abspath(arg)
        elif opt == "-d":
            dout = os.path.abspath(arg) + "/"
            os.makedirs(dout, exist_ok=True)
            fout_ext = ".txt"
        elif opt == "-t":
            fout_ext = ".txt"
        elif opt == "-f":
            scan = "full"
        elif opt == "-a":
            scan = "count"
        elif opt == "-s":
            scan = "IP"

    tempXML = []
    if os.path.isdir(inXML):
        tempXML = [f for f in glob.glob(os.path.abspath(inXML + "/*")) if os.path.isfile(f) and f.endswith(".xml")]
    elif os.path.isfile(inXML):
        tempXML.append(os.path.abspath(inXML))
    else:
        print(f"{sys.argv[0]}: Could not find Scalp XML file: {inXML}")
        sys.exit(1)

    if os.path.isfile(fdtd) and hasattr(etree, "DTD"):
        try:
            with open(fdtd, "r") as xdtd:
                vdtd = etree.DTD(xdtd)
        except Exception:
            vdtd = None

    for fXML in tempXML:
        p_scalp = xparse(fXML, vdtd)
        if p_scalp is None:
            continue

        close_after = False
        if fout_ext:
            out_name = f"{dout}sexr_{fnow}.txt"
            fhandle = open(out_name, "w", encoding="utf-8")
            close_after = True

        if scan == "full":
            iter_node(p_scalp, "", fhandle)
        else:
            item_cnt_iter(p_scalp, "", fhandle, scan_mode=scan)

        if close_after:
            fhandle.close()
            print(f"{sys.argv[0]}: Wrote output to {out_name}")

    print(f"{sys.argv[0]}: Done")


if __name__ == "__main__":
    main()
