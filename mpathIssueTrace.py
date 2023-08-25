#!/usr/bin/python3
from bcc import BPF

b = BPF(src_file="mpathIssueTrace.c")


b.attach_tracepoint(tp="block:block_rq_issue", fn_name="traceIssue")
b.attach_tracepoint(tp="block:block_rq_complete", fn_name="traceComplete")
b.attach_tracepoint(tp="block:block_rq_remap", fn_name="traceRemap")

b.trace_print()
