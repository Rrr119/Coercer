#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : paths.py
# Author             : Podalirius (@podalirius_)
# Date created       : 16 Nov 2026


from coercer.core.Filter import Filter
from coercer.core.Reporter import reporter
from coercer.core.utils import generate_exploit_path_from_template
from coercer.structures import EscapeCodes


def action_paths(available_methods, options):
    """
    Function action_paths(available_methods, options)

    Lists all the available coerce methods along with the exploit paths
    (UNC paths) that can be used to coerce an authentication.
    """
    filter = Filter(
        filter_method_name=options.filter_method_name,
        filter_protocol_name=options.filter_protocol_name,
        filter_pipe_name=options.filter_pipe_name,
    )

    listener = (
        getattr(options, "path_ip", None)
        or getattr(options, "ip_address", None)
        or "LISTENER"
    )

    for method_type in available_methods.keys():
        for category in sorted(available_methods[method_type].keys()):
            for method in sorted(available_methods[method_type][category].keys()):
                instance = available_methods[method_type][category][method]["class"]

                if not filter.method_matches_filter(instance):
                    continue

                reporter.print(
                    ("[%s] " % category, EscapeCodes.BOLD_BRIGHT_BLUE),
                    "%s (opnum %d)"
                    % (instance.function["name"], instance.function["opnum"]),
                    symbol=("+", EscapeCodes.BRIGHT_GREEN),
                )

                # Access points (named pipes and TCP endpoints)
                for access_method in instance.access.get("ncan_np", []):
                    if filter.pipe_matches_filter(access_method["namedpipe"]):
                        reporter.print_info(
                            "   ",
                            "Pipe: %s (uuid: %s, version: %s)"
                            % (
                                access_method["namedpipe"],
                                access_method["uuid"],
                                access_method["version"],
                            ),
                        )
                for access_method in instance.access.get("ncacn_ip_tcp", []):
                    reporter.print_info(
                        "   ",
                        "TCP endpoint: (uuid: %s, version: %s)"
                        % (access_method["uuid"], access_method["version"]),
                    )

                # Exploit paths usable to coerce an authentication
                exploit_paths = instance.generate_exploit_templates(
                    desired_auth_type=options.auth_type
                )
                if len(exploit_paths) != 0:
                    reporter.print_info(
                        "   ",
                        "Usable coerce paths (listener: %s):" % listener,
                    )
                    for auth_type, template in exploit_paths:
                        exploitpath = generate_exploit_path_from_template(
                            template=template,
                            listener=listener,
                            http_listen_port=options.http_port,
                            smb_listen_port=options.smb_port,
                        )
                        reporter.print(
                            "      ",
                            ("[%s] " % auth_type, EscapeCodes.BOLD_BRIGHT_BLUE),
                            (exploitpath.rstrip("\x00"), EscapeCodes.BRIGHT_YELLOW),
                        )
